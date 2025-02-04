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

/// The core fuzzer responsible for generating and executing programs.
public class TargetedMutationEngine: FuzzEngine {
    // The number of consecutive mutations to apply to a sample.
    private let numConsecutiveMutations: Int

    public init(numConsecutiveMutations: Int) {
        self.numConsecutiveMutations = numConsecutiveMutations
        super.init(name: "MutationEngine")
    }

    /// Perform one round of fuzzing.
    ///
    /// High-level fuzzing algorithm:
    ///     Make 3 attempts for a targeted (location, type) generation.
    ///     let parent = pickSampleFromCorpus()
    ///     repeat N times:
    ///         let current = mutate(parent)
    ///         execute(current)
    ///         if current produced crashed:
    ///             output current
    ///         elif current resulted in a runtime exception or a time out:
    ///             // do nothing
    ///         elif current produced new, interesting behaviour:
    ///             minimize and add to corpus
    ///         else
    ///             parent = current
    ///
    ///
    /// This ensures that samples will be mutated multiple times as long
    /// as the intermediate results do not cause a runtime exception.
    public override func fuzzOne(_ group: DispatchGroup) {
        // === Targeted (location, type) generation attempts ===
        //logger.info(">>> Starting targeted (location, type) generation attempts")
        
        // Make 3 targeted attempts.
        for attempt in 1...3 {
            logger.info("  Targeted Attempt \(attempt):")
            
            if let corpus = fuzzer.corpus as? BasicCorpus,
            let evaluator = fuzzer.evaluator as? ProgramCoverageEvaluator,
            let (donor1, donor2, targetLocation, targetType) = corpus.findDonorPairForInterestingCombination(evaluator: evaluator) {
            
                //logger.info("    Found donor pair:")
                //logger.info("      donor1 = \(donor1.id)")
                //logger.info("      donor2 = \(donor2.id)")
                //logger.info("    Target combination: (location, type) = (\(targetLocation), \(targetType))")
                
                if let combineMutator = fuzzer.mutators.first(where: { $0 is CombineMutator }) as? CombineMutator {
                    if let targetedProgram = combineMutator.targetedCombine(donor1: donor1,
                                                                            donor2: donor2,
                                                                            targetLocation: targetLocation,
                                                                            targetType: targetType,
                                                                            fuzzer: fuzzer) {
                        execute(targetedProgram)
                        //logger.info("    Execution outcome: \(outcome)")
                        
                        // Check if the targeted combination was successfully triggered.
                        // If wouldBeInteresting returns false, then the target is no longer unseen.
                        if !evaluator.wouldBeInteresting(location: targetLocation, type: targetType) {
                            logger.info("      Success: Generated target combination (location: \(targetLocation), type: \(targetType))")
                        } else {
                            logger.info("      Failure: Target combination (location: \(targetLocation), type: \(targetType)) not triggered")
                        }
                    } else {
                        logger.info("    CombineMutator.targetedCombine failed to produce a program for (location: \(targetLocation), type: \(targetType))")
                    }
                } else {
                    logger.warning("    No CombineMutator available for targeted generation!")
                }
            } else {
                logger.info("    No donor pair found for targeted generation on attempt \(attempt).")
            }
        }

        var parent = fuzzer.corpus.randomElementForMutating()
        parent = prepareForMutating(parent)
        for _ in 0..<numConsecutiveMutations {
            // TODO: factor out code shared with the HybridEngine?
            var mutator = fuzzer.mutators.randomElement()
            let maxAttempts = 10
            var mutatedProgram: Program? = nil
            for _ in 0..<maxAttempts {
                //logger.info("  Attempt \(attempt+1) with mutator \(mutator.name)")
                if let result = mutator.mutate(parent, for: fuzzer) {
                    // Success!
                    result.contributors.formUnion(parent.contributors)
                    mutator.addedInstructions(result.size - parent.size)
                    mutatedProgram = result
                    break
                } else {
                    // Try a different mutator.
                    mutator.failedToGenerate()
                    mutator = fuzzer.mutators.randomElement()
                }
            }

            guard let program = mutatedProgram else {
                logger.warning("Could not mutate sample, giving up. Sample:\n\(FuzzILLifter().lift(parent))")
                continue
            }

            assert(program !== parent)
            let outcome = execute(program)

            // Mutate the program further if it succeeded.
            if .succeeded == outcome {
                parent = program
            }
        }
    }

    /// Pre-processing of programs to facilitate mutations on them.
    private func prepareForMutating(_ program: Program) -> Program {
        let b = fuzzer.makeBuilder()
        b.buildPrefix()
        b.append(program)
        return b.finalize()
    }
}
