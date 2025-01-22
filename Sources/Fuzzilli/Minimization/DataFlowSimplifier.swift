// Copyright 2025 Google LLC
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

/// Simplifies the data flow of a program.
///
/// This essentially attempts to remove intermediate instructions in a data flow chain if they are not important. For example:
///
///     v3 <- Foo
///     v4 <- Bar v3
///     v5 <- Baz v4
///
/// If `Baz` is the interesting operation here, the `Bar` may be unnecessary and so we simplify this program to
///
///     v3 <- Foo
///     v5 <- Baz v3
///
/// By removing `Bar` and replacing all uses of its output with one of its inputs. We assume that one of the inputs
/// is probably the best fit for a replacement. For cases such as `CreateNamedVariable` or `Reassign`, using
/// an input is definitely the right choice. In other cases, such as arithmetic operations, the input should at least have
/// roughly the right type.
struct DataFlowSimplifier: Reducer {
    func reduce(with helper: MinimizationHelper) {
        // Compute all candidates: intermediate operations in a data flow chain.
        var candidates = [Int]()
        var uses = VariableMap<Int>()
        for instr in helper.code {
            for input in instr.inputs {
                uses[input]? += 1
            }

            // For now, we only consider simple instructions as candidates.
            guard instr.isSimple else  { continue }
            // The instruction must have at least one output and one input,
            // otherwise it wouldn't be an intermediate node.
            guard instr.numOutputs > 0 else { continue }
            guard instr.numInputs > 0 else { continue }

            candidates.append(instr.index)
            for output in instr.outputs {
                uses[output] = 0
            }
        }

        // Remove those candidates whose outputs aren't used.
        candidates = candidates.filter({ helper.code[$0].allOutputs.map({ uses[$0]! }).reduce(0, +) > 0 })

        // Finally try to remove each remaining candidate.
        for candidate in candidates {
            var newCode = Code()
            var replacements = VariableMap<Variable>()
            for instr in helper.code {
                if instr.index == candidate {
                    assert(instr.numInputs > 0)
                    assert(instr.numOutputs > 0)
                    // Pick a random input as replacement. Here we could attempt to be smarter and
                    // for example find an input that seems more fitting, or we could try to apply
                    // some heursitic, such as using the input with the most uses itself.
                    let replacement = chooseUniform(from: instr.inputs)
                    for output in instr.allOutputs {
                        assert(uses.contains(output))
                        replacements[output] = replacement
                    }
                    assert(instr.allOutputs.map({ uses[$0]! }).reduce(0, +) > 0)
                    // Replace the instruction with a "compatible" Nop (same in- and outputs)
                    newCode.append(helper.nop(for: instr))
                } else {
                    // Keep this instruction but potentially change the inputs.
                    let newInouts = instr.inouts.map({ replacements[$0] ?? $0 })
                    let newInstr = Instruction(instr.op, inouts: newInouts, flags: instr.flags)
                    newCode.append(newInstr)
                }
            }
            helper.testAndCommit(newCode)
        }
    }
}

