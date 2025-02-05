// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import libcoverage

/// Represents a set of newly discovered CFG edges in the target program.
public class CovEdgeSet: ProgramAspects {
    private var numEdges: UInt32
    fileprivate var edges: UnsafeMutablePointer<UInt32>?

    public var visitedLocations: [UInt32]
    public var visitedTypes: [UInt32]

    init(edges: UnsafeMutablePointer<UInt32>?, numEdges: UInt32, visitedLocations: [UInt32], visitedTypes: [UInt32]) {
        self.numEdges = numEdges
        self.edges = edges

        self.visitedLocations = visitedLocations
        self.visitedTypes = visitedTypes

        super.init(outcome: .succeeded)
    }

    deinit {
        free(edges)
    }

    /// The number of aspects is simply the number of newly discovered coverage edges. (not counting locations/types).
    public override var count: UInt32 {
        return numEdges
    }

    public override var description: String {
        return """
        new coverage:
          \(numEdges) newly discovered code edges,
          visited \(visitedLocations.count) locations,
          visited \(visitedTypes.count) types
        """
    }

    /// Returns an array of all the newly discovered edges of this CovEdgeSet.
    ///
    /// This adds additional copies, but is only hit when new programs are added to the corpus
    /// It is used by corpus schedulers such as MarkovCorpus that require knowledge of which samples trigger which edges
    public func getEdges() -> [UInt32] {
        return Array(UnsafeBufferPointer(start: edges, count: Int(count)))
    }

    public static func == (lhsEdges: CovEdgeSet, rhsEdges: CovEdgeSet) -> Bool {
        if lhsEdges.outcome != rhsEdges.outcome { return false }
        if lhsEdges.count != rhsEdges.count { return false }
        for i in 0..<Int(lhsEdges.count) {
            if lhsEdges.edges![i] != rhsEdges.edges![i] {
                return false
            }
        }
        return true
    }

    // Updates the internal state to match the provided collection
    fileprivate func setEdges<T: Collection>(_ collection: T) where T.Element == UInt32 {
        precondition(collection.count <= self.count)
        self.numEdges = UInt32(collection.count)
        for (i, edge) in collection.enumerated() {
            self.edges![i] = edge
        }
    }

    public func setTypes<T: Collection>(_ collection: T) where T.Element == UInt32 {
        self.visitedTypes = Array(collection)
    }

    public func setLocations<T: Collection>(_ collection: T) where T.Element == UInt32 {
        self.visitedLocations = Array(collection)
    }
}

public class ProgramCoverageEvaluator: ComponentBase, ProgramEvaluator {
    /// Counts the number of instances. Used to create unique shared memory regions in every instance.
    private static var instances = 0

    /// Whether per-edge hit counts should be tracked as well.
    /// These are expensive to compute, so this need to be enabled explicitly.
    private var shouldTrackEdgeCounts : Bool

    /// Keep track of how often an edge has been reset. Frequently set/cleared edges will be ignored
    private var resetCounts : [UInt32:UInt64] = [:]

    /// How often an edge may be reset at most before it is considered non-deterministic.
    /// In that case, the edge is marked as found, but will not be considered an aspect of any program.
    private let maxResetCount : UInt64 = 1000

    /// The current edge coverage percentage.
    public var currentScore: Double {
        return Double(context.found_edges) / Double(context.num_edges - (1 << 18))
    }

    public var codeEdgeThreshold: UInt32 {
        return context.num_edges - (1 << 18)
    }

    public var currentTypeScore: UInt32 {
        return UInt32(context.found_types)
    }

    /// Context for the C library.
    private var context = libcoverage.cov_context()

    public init(runner: ScriptRunner) {
        // In order to keep clean abstractions, any corpus scheduler requiring edge counting
        // needs to call EnableEdgeTracking(), via downcasting of ProgramEvaluator
        self.shouldTrackEdgeCounts = false

        super.init(name: "Coverage")

        let id = ProgramCoverageEvaluator.instances
        ProgramCoverageEvaluator.instances += 1

        context.id = Int32(id)
        guard libcoverage.cov_initialize(&context) == 0 else {
            fatalError("Could not initialize libcoverage")
        }
#if os(Windows)
        runner.setEnvironmentVariable("SHM_ID", to: "shm_id_\(GetCurrentProcessId())_\(id)")
#else
        runner.setEnvironmentVariable("SHM_ID", to: "shm_id_\(getpid())_\(id)")
#endif

    }

    public func enableEdgeTracking() {
        assert(!isInitialized) // This should only be called prior to initialization
        shouldTrackEdgeCounts = true
    }


    public func getEdgeHitCounts() -> [UInt32] {
        var edgeCounts = libcoverage.edge_counts()
        let result = libcoverage.cov_get_edge_counts(&context, &edgeCounts)
        if result == -1 {
            logger.error("Error retrifying smallest hit count edges")
            return []
        }
        var edgeArray = Array(UnsafeBufferPointer(start: edgeCounts.edge_hit_count, count: Int(edgeCounts.count)))

        // Clear all edges that have hit their reset limits
        for (edge, count) in resetCounts {
            if count >= maxResetCount {
                edgeArray[Int(edge)] = 0
            }
        }

        return edgeArray
    }

    override func initialize() {
        // Must clear the shared memory bitmap before every execution
        fuzzer.registerEventListener(for: fuzzer.events.PreExecute) { execution in
            libcoverage.cov_clear_bitmap(&self.context)
        }

        // Unlink the shared memory regions on shutdown
        fuzzer.registerEventListener(for: fuzzer.events.Shutdown) { _ in
            libcoverage.cov_shutdown(&self.context)
        }

        let _ = fuzzer.execute(Program(), purpose: .startup)
        libcoverage.cov_finish_initialization(&context, shouldTrackEdgeCounts ? 1 : 0)
        logger.info("Initialized, \(context.num_edges - (1 << 18)) edges")
    }

    public func evaluate(_ execution: Execution) -> ProgramAspects? {
        assert(execution.outcome == .succeeded)
        var newEdgeSet = libcoverage.edge_set()
        let result = libcoverage.cov_evaluate(&context, &newEdgeSet)
        guard result != -1 else {
            logger.error("Could not evaluate sample")
            return nil
        }

        if result == 1 {
            // 1) Fetch newly visited locations
            var visitedLocations = libcoverage.edge_set()
            libcoverage.cov_get_visited_locations(&context, &visitedLocations)
            let locationsArray = Array(
                UnsafeBufferPointer(start: visitedLocations.edge_indices,
                                    count: Int(visitedLocations.count))
            )

            // 2) Fetch newly visited types
            var visitedTypes = libcoverage.edge_set()
            libcoverage.cov_get_visited_types(&context, &visitedTypes)
            let typesArray = Array(
                UnsafeBufferPointer(start: visitedTypes.edge_indices,
                                    count: Int(visitedTypes.count))
            )

            // 3) Construct our CovEdgeSet
            return CovEdgeSet(
                edges: newEdgeSet.edge_indices,
                numEdges: newEdgeSet.count,
                visitedLocations: locationsArray,
                visitedTypes: typesArray
            )
        } else {
            //assert(newEdgeSet.edge_indices == nil && newEdgeSet.count == 0)
            return nil
        }
    }

    public func evaluateCrash(_ execution: Execution) -> ProgramAspects? {
        assert(execution.outcome.isCrash())
        let result = libcoverage.cov_evaluate_crash(&context)
        guard result != -1 else {
            logger.error("Could not evaluate crash")
            return nil
        }

        if result == 1 {
            // For minimization of crashes we only care about the outcome, not the edges covered.
            return ProgramAspects(outcome: execution.outcome)
        } else {
            return nil
        }
    }

    public func hasAspects(_ execution: Execution, _ aspects: ProgramAspects) -> Bool {
        guard execution.outcome == aspects.outcome else {
            return false
        }

        if execution.outcome.isCrash() {
            // For crashes, we don't care about the edges that were triggered, just about the outcome itself.
            return true
        }

        guard let edgeSet = aspects as? CovEdgeSet else {
            fatalError("Invalid aspects passed to hasAspects")
        }

        let result = libcoverage.cov_compare_equal(&context, edgeSet.edges, edgeSet.count)
        if result == -1 {
            logger.error("Could not compare progam executions")
        }
        return result == 1
    }

    public func computeAspectIntersection(of program: Program, with aspects: ProgramAspects) -> ProgramAspects? {
        guard let firstCovEdgeSet = aspects as? CovEdgeSet else {
            logger.fatal("Coverage Evaluator received non coverage aspects")
        }

        // Mark all edges in the provided aspects as undiscovered so they can be retriggered during the next execution.
        resetAspects(firstCovEdgeSet)

        // Execute the program and collect coverage information.
        let execution = fuzzer.execute(program, purpose: .checkForDeterministicBehavior)
        guard execution.outcome == .succeeded else { return nil }
        guard let secondCovEdgeSet = evaluate(execution) as? CovEdgeSet else { return nil }

        // Compute the intersection of code edges.
        let firstEdgeSet = Set(UnsafeBufferPointer(start: firstCovEdgeSet.edges, count: Int(firstCovEdgeSet.count)))
        let secondEdgeSet = Set(UnsafeBufferPointer(start: secondCovEdgeSet.edges, count: Int(secondCovEdgeSet.count)))
        let intersectedEdgeSet = secondEdgeSet.intersection(firstEdgeSet)
        guard intersectedEdgeSet.count != 0 else { return nil }

        // Compute the intersection of visited types.
        let firstTypeSet = Set(firstCovEdgeSet.visitedTypes)
        let secondTypeSet = Set(secondCovEdgeSet.visitedTypes)
        let intersectedTypes = Array(firstTypeSet.intersection(secondTypeSet))

        // Compute the intersection of visited locations.
        let firstLocationSet = Set(firstCovEdgeSet.visitedLocations)
        let secondLocationSet = Set(secondCovEdgeSet.visitedLocations)
        let intersectedLocations = Array(firstLocationSet.intersection(secondLocationSet))

        // Reset all edges that were only triggered by the 2nd execution.
        for edge in secondEdgeSet.subtracting(firstEdgeSet) {
            resetEdge(edge)
        }

        // visited locations and types are automatically reset in the REPRL loop

        // Here we reuse one of the existing CovEdgeSets instead of creating a new one to avoid a malloc() and free() of the backing buffer.
        let intersectedCovEdgeSet = secondCovEdgeSet
        intersectedCovEdgeSet.setEdges(intersectedEdgeSet)
        intersectedCovEdgeSet.setTypes(intersectedTypes)
        intersectedCovEdgeSet.setLocations(intersectedLocations)

        return intersectedCovEdgeSet
    }

    public func exportState() -> Data {
        var state = Data()
        state.append(Data(bytes: &context.num_edges, count: 4))
        state.append(Data(bytes: &context.bitmap_size, count: 4))
        state.append(Data(bytes: &context.found_edges, count: 4))
        state.append(Data(bytes: &context.found_types, count: 4))
        state.append(context.virgin_bits, count: Int(context.bitmap_size))
        state.append(context.crash_bits, count: Int(context.bitmap_size))
        return state
    }

    public func importState(_ state: Data) throws {
        assert(isInitialized)
        let headerSize = 16     // 3 x 4 bytes: num_edges, bitmap_size, found_edges. See exportState() above

        guard state.count == headerSize + Int(context.bitmap_size) * 2 else {
            throw FuzzilliError.evaluatorStateImportError("Cannot import coverage state as it has an unexpected size. Ensure all instances use the same build of the target")
        }

        let numEdges = state.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self) }
        let bitmapSize = state.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
        let foundEdges = state.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt32.self) }
        let foundTypes = state.withUnsafeBytes { $0.load(fromByteOffset: 12, as: UInt32.self) }


        guard bitmapSize == context.bitmap_size && numEdges == context.num_edges else {
            throw FuzzilliError.evaluatorStateImportError("Cannot import coverage state due to different bitmap sizes. Ensure all instances use the same build of the target")
        }

        context.found_edges = foundEdges
        context.found_types = foundTypes

        var start = state.startIndex + headerSize
        state.copyBytes(to: context.virgin_bits, from: start..<start + Int(bitmapSize))
        start += Int(bitmapSize)
        state.copyBytes(to: context.crash_bits, from: start..<start + Int(bitmapSize))

        logger.info("Imported existing coverage state with \(foundEdges) edges already discovered")
    }

    public func resetState() {
        resetCounts = [:]
        libcoverage.cov_reset_state(&context)
    }

    public func wouldBeInteresting(location: UInt32, type: UInt32) -> Bool {
        return libcoverage.cov_would_be_interesting(&context, location, type) == 1
    }


    // TODO See if we want to count the number of non-deterministic edges and expose them through the fuzzer statistics (if deterministic mode is enabled)
    private func resetEdge(_ edge: UInt32) {
        resetCounts[edge] = (resetCounts[edge] ?? 0) + 1
        if resetCounts[edge]! <= maxResetCount {
            libcoverage.cov_clear_edge_data(&context, edge)
        }
    }

    private func resetAspects(_ aspects: CovEdgeSet) {
        for i in 0..<Int(aspects.count) {
            resetEdge(aspects.edges![i])
        }
    }
}
