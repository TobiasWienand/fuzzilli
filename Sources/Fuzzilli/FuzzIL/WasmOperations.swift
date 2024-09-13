// Copyright 2022 Google LLC
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

public class WasmOperation: Operation {
    var inputTypes: [ILType]
    // If this wasm operation does not have an output, it will have .nothing as an output type but its numOutputs will be 0.
    var outputType: ILType
    var innerOutputTypes: [ILType]

    init(inputTypes: [ILType] = [], outputType: ILType = .nothing, innerOutputTypes: [ILType] = [], firstVariadicInput: Int = -1, attributes: Attributes = [], requiredContext: Context, contextOpened: Context = .empty) {
        self.inputTypes = inputTypes
        self.outputType = outputType
        self.innerOutputTypes = innerOutputTypes
        super.init(numInputs: inputTypes.count, numOutputs: outputType == .nothing ? 0 : 1, numInnerOutputs: innerOutputTypes.count, firstVariadicInput: firstVariadicInput, attributes: attributes, requiredContext: requiredContext, contextOpened: contextOpened)
    }

    struct WasmConstants {
       // This constant limits the amount of *declared* memory. At runtime, memory can grow up to only a limit based on the architecture type.
       static let specMaxWasmMem32Pages: Int = 65536 // 4GB
   }

}

final class Consti64: WasmOperation {
    override var opcode: Opcode { .consti64(self) }
    let value: Int64

    init(value: Int64) {
        self.value = value
        super.init(outputType: .wasmi64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Consti32: WasmOperation {
    override var opcode: Opcode { .consti32(self) }
    let value: Int32

    init(value: Int32) {
        self.value = value
        super.init(outputType: .wasmi32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Constf32: WasmOperation {
    override var opcode: Opcode { .constf32(self) }
    var value: Float32

    init(value: Float32) {
        self.value = value
        super.init(outputType: .wasmf32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Constf64: WasmOperation {
    override var opcode: Opcode { .constf64(self) }
    var value: Float64

    init(value: Float64) {
        self.value = value
        super.init(outputType: .wasmf64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

//
// Control Instructions
//

final class WasmReturn: WasmOperation {
    override var opcode: Opcode { .wasmReturn(self) }

    let returnType: ILType

    init(returnType: ILType) {
        self.returnType = returnType
        if returnType.Is(.nothing) {
            super.init(inputTypes: [], attributes: [.isPure, .isJump], requiredContext: [.wasmFunction])
        } else {
            super.init(inputTypes: [returnType], attributes: [.isPure, .isJump], requiredContext: [.wasmFunction])
        }
    }
}

//
// Numerical Instructions
//

//
// Integer Comparison Operations
//

public enum WasmIntegerCompareOpKind: UInt8, CaseIterable {
    case Eq   = 0
    case Ne   = 1
    case Lt_s = 2
    case Lt_u = 3
    case Gt_s = 4
    case Gt_u = 5
    case Le_s = 6
    case Le_u = 7
    case Ge_s = 8
    case Ge_u = 9
}

extension WasmIntegerCompareOpKind: CustomStringConvertible {
    public var description: String {
        switch self {
        case .Eq: return "eq"
        case .Ne: return "ne"
        case .Lt_s: return "lt_s"
        case .Lt_u: return "lt_u"
        case .Gt_s: return "gt_s"
        case .Gt_u: return "gt_u"
        case .Le_s: return "le_s"
        case .Le_u: return "le_u"
        case .Ge_s: return "ge_s"
        case .Ge_u: return "ge_u"
        }
    }
}

final class Wasmi32CompareOp: WasmOperation {
    override var opcode: Opcode { .wasmi32CompareOp(self) }

    let compareOpKind: WasmIntegerCompareOpKind


    init(compareOpKind: WasmIntegerCompareOpKind) {
        self.compareOpKind = compareOpKind
        super.init(inputTypes: [.wasmi32, .wasmi32], outputType: .wasmi32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmi64CompareOp: WasmOperation {
    override var opcode: Opcode { .wasmi64CompareOp(self) }

    let compareOpKind: WasmIntegerCompareOpKind

    init(compareOpKind: WasmIntegerCompareOpKind) {
        self.compareOpKind = compareOpKind
        super.init(inputTypes: [.wasmi64, .wasmi64], outputType: .wasmi32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

//
// Float Comparison Operations
//

public enum WasmFloatCompareOpKind: UInt8, CaseIterable {
    case Eq = 0
    case Ne = 1
    case Lt = 2
    case Gt = 3
    case Le = 4
    case Ge = 5
}

extension WasmFloatCompareOpKind: CustomStringConvertible {
    public var description: String {
        switch self {
        case .Eq: return "eq"
        case .Ne: return "ne"
        case .Lt: return "lt"
        case .Gt: return "gt"
        case .Le: return "le"
        case .Ge: return "ge"
        }
    }
}

final class Wasmf32CompareOp: WasmOperation {
    override var opcode: Opcode { .wasmf32CompareOp(self) }

    let compareOpKind: WasmFloatCompareOpKind

    init(compareOpKind: WasmFloatCompareOpKind) {
        self.compareOpKind = compareOpKind
        super.init(inputTypes: [.wasmf32, .wasmf32], outputType: .wasmi32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmf64CompareOp: WasmOperation {
    override var opcode: Opcode { .wasmf64CompareOp(self) }

    let compareOpKind: WasmFloatCompareOpKind

    init(compareOpKind: WasmFloatCompareOpKind) {
        self.compareOpKind = compareOpKind
        super.init(inputTypes: [.wasmf64, .wasmf64], outputType: .wasmi32, attributes: [.isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmi32EqualZero: WasmOperation {
    override var opcode: Opcode { .wasmi32EqualZero(self) }

    init() {
        super.init(inputTypes: [.wasmi32], outputType: .wasmi32, attributes: [.isPure], requiredContext: [.wasmFunction])
    }
}

final class Wasmi64EqualZero: WasmOperation {
    override var opcode: Opcode { .wasmi64EqualZero(self) }

    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmi32, attributes: [.isPure], requiredContext: [.wasmFunction])
    }
}

//
// Integer Unary and Binary Operations
//

public enum WasmIntegerUnaryOpKind: UInt8, CaseIterable {
    // Just like with the i32 binary operators, ordering here is imporant.
    case Clz = 0
    case Ctz = 1
    case Popcnt = 2
}

public enum WasmIntegerBinaryOpKind: UInt8, CaseIterable {
    // This ordering here is important, we just take the offset and add it to a base constant to encode the binary representation.
    // See the `lift` function in WasmLifter.swift and the case .wasmi32BinOp
    // The values for this can be found here: https://webassembly.github.io/spec/core/binary/instructions.html#numeric-instructions
    case Add = 0
    case Sub = 1
    case Mul = 2
    case Div_s = 3
    case Div_u = 4
    case Rem_s = 5
    case Rem_u = 6
    case And = 7
    case Or = 8
    case Xor = 9
    case Shl = 10
    case Shr_s = 11
    case Shr_u = 12
    case Rotl = 13
    case Rotr = 14
}

final class Wasmi32BinOp: WasmOperation {
    override var opcode: Opcode { .wasmi32BinOp(self) }

    let binOpKind: WasmIntegerBinaryOpKind

    init(binOpKind: WasmIntegerBinaryOpKind) {
        self.binOpKind = binOpKind
        super.init(inputTypes: [.wasmi32, .wasmi32], outputType: .wasmi32, attributes: [.isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmi64BinOp: WasmOperation {
    override var opcode: Opcode { .wasmi64BinOp(self) }

    let binOpKind: WasmIntegerBinaryOpKind

    init(binOpKind: WasmIntegerBinaryOpKind) {
        self.binOpKind = binOpKind
        super.init(inputTypes: [.wasmi64, .wasmi64], outputType: .wasmi64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmi32UnOp: WasmOperation {
    override var opcode: Opcode { .wasmi32UnOp(self) }

    let unOpKind: WasmIntegerUnaryOpKind

    init(unOpKind: WasmIntegerUnaryOpKind) {
        self.unOpKind = unOpKind
        super.init(inputTypes: [.wasmi32], outputType: .wasmi32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}


final class Wasmi64UnOp: WasmOperation {
    override var opcode: Opcode { .wasmi64UnOp(self) }

    let unOpKind: WasmIntegerUnaryOpKind

    init(unOpKind: WasmIntegerUnaryOpKind) {
        self.unOpKind = unOpKind
        super.init(inputTypes: [.wasmi64], outputType: .wasmi64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

//
// Float Unary and Binary Operations
//

public enum WasmFloatUnaryOpKind: UInt8, CaseIterable {
    // Just like with the i32 binary operators, ordering here is imporant.
    case Abs = 0
    case Neg = 1
    case Ceil = 2
    case Floor = 3
    case Trunc = 4
    case Nearest = 5
    case Sqrt = 6
}

public enum WasmFloatBinaryOpKind: UInt8, CaseIterable {
    // This ordering here is important, we just take the offset and add it to a base constant to encode the binary representation.
    // See the `lift` function in WasmLifter.swift and the case .wasmf32BinOp
    // The values for this can be found here: https://webassembly.github.io/spec/core/binary/instructions.html#numeric-instructions
    case Add = 0
    case Sub = 1
    case Mul = 2
    case Div = 3
    case Min = 4
    case Max = 5
    case Copysign = 6
}

final class Wasmf32BinOp: WasmOperation {
    override var opcode: Opcode { .wasmf32BinOp(self) }

    let binOpKind: WasmFloatBinaryOpKind

    init(binOpKind: WasmFloatBinaryOpKind) {
        self.binOpKind = binOpKind
        super.init(inputTypes: [.wasmf32, .wasmf32], outputType: .wasmf32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmf64BinOp: WasmOperation {
    override var opcode: Opcode { .wasmf64BinOp(self) }

    let binOpKind: WasmFloatBinaryOpKind

    init(binOpKind: WasmFloatBinaryOpKind) {
        self.binOpKind = binOpKind
        super.init(inputTypes: [.wasmf64, .wasmf64], outputType: .wasmf64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmf32UnOp: WasmOperation {
    override var opcode: Opcode { .wasmf32UnOp(self)}

    let unOpKind: WasmFloatUnaryOpKind

    init(unOpKind: WasmFloatUnaryOpKind) {
        self.unOpKind = unOpKind
        super.init(inputTypes: [.wasmf32], outputType: .wasmf32, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

final class Wasmf64UnOp: WasmOperation {
    override var opcode: Opcode { .wasmf64UnOp(self)}

    let unOpKind: WasmFloatUnaryOpKind

    init(unOpKind: WasmFloatUnaryOpKind) {
        self.unOpKind = unOpKind
        super.init(inputTypes: [.wasmf64], outputType: .wasmf64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

//
// Numerical Conversion Operations
//

final class WasmWrapi64Toi32: WasmOperation {
    override var opcode: Opcode { .wasmWrapi64Toi32(self) }

    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmi32, attributes: [.isPure], requiredContext: [.wasmFunction])
    }
}

final class WasmTruncatef32Toi32: WasmOperation {
    override var opcode: Opcode { .wasmTruncatef32Toi32(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf32], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncatef64Toi32: WasmOperation {
    override var opcode: Opcode { .wasmTruncatef64Toi32(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf64], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmExtendi32Toi64: WasmOperation {
    override var opcode: Opcode { .wasmExtendi32Toi64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmi32], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncatef32Toi64: WasmOperation {
    override var opcode: Opcode { .wasmTruncatef32Toi64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf32], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncatef64Toi64: WasmOperation {
    override var opcode: Opcode { .wasmTruncatef64Toi64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf64], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmConverti32Tof32: WasmOperation {
    override var opcode: Opcode { .wasmConverti32Tof32(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmi32], outputType: .wasmf32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmConverti64Tof32: WasmOperation {
    override var opcode: Opcode { .wasmConverti64Tof32(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmi64], outputType: .wasmf32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmDemotef64Tof32: WasmOperation {
    override var opcode: Opcode { .wasmDemotef64Tof32(self) }

    init() {
        super.init(inputTypes: [.wasmf64], outputType: .wasmf32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmConverti32Tof64: WasmOperation {
    override var opcode: Opcode { .wasmConverti32Tof64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmi32], outputType: .wasmf64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmConverti64Tof64: WasmOperation {
    override var opcode: Opcode { .wasmConverti64Tof64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmi64], outputType: .wasmf64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmPromotef32Tof64: WasmOperation {
    override var opcode: Opcode { .wasmPromotef32Tof64(self) }

    init() {
        super.init(inputTypes: [.wasmf32], outputType: .wasmf64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmReinterpretf32Asi32: WasmOperation {
    override var opcode: Opcode { .wasmReinterpretf32Asi32(self) }

    init() {
        super.init(inputTypes: [.wasmf32], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmReinterpretf64Asi64: WasmOperation {
    override var opcode: Opcode { .wasmReinterpretf64Asi64(self) }

    init() {
        super.init(inputTypes: [.wasmf64], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmReinterpreti32Asf32: WasmOperation {
    override var opcode: Opcode { .wasmReinterpreti32Asf32(self) }

    init() {
        super.init(inputTypes: [.wasmi32], outputType: .wasmf32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmReinterpreti64Asf64: WasmOperation {
    override var opcode: Opcode { .wasmReinterpreti64Asf64(self) }

    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmf64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmSignExtend8Intoi32: WasmOperation {
    override var opcode: Opcode { .wasmSignExtend8Intoi32(self) }

    init() {
        super.init(inputTypes: [.wasmi32], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmSignExtend16Intoi32: WasmOperation {
    override var opcode: Opcode { .wasmSignExtend16Intoi32(self) }

    init() {
        super.init(inputTypes: [.wasmi32], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmSignExtend8Intoi64: WasmOperation {
    override var opcode: Opcode { .wasmSignExtend8Intoi64(self) }

    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmSignExtend16Intoi64: WasmOperation {
    override var opcode: Opcode { .wasmSignExtend16Intoi64(self) }

    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmSignExtend32Intoi64: WasmOperation {
    override var opcode: Opcode { .wasmSignExtend32Intoi64(self) }

    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncateSatf32Toi32: WasmOperation {
    override var opcode: Opcode { .wasmTruncateSatf32Toi32(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf32], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncateSatf64Toi32: WasmOperation {
    override var opcode: Opcode { .wasmTruncateSatf64Toi32(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf64], outputType: .wasmi32, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncateSatf32Toi64: WasmOperation {
    override var opcode: Opcode { .wasmTruncateSatf32Toi64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf32], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

final class WasmTruncateSatf64Toi64: WasmOperation {
    override var opcode: Opcode { .wasmTruncateSatf64Toi64(self) }

    let isSigned: Bool

    init(isSigned: Bool) {
        self.isSigned = isSigned
        super.init(inputTypes: [.wasmf64], outputType: .wasmi64, attributes: [.isPure], requiredContext: .wasmFunction)
    }
}

//
// Global Instructions
//

public enum WasmGlobal {
    case wasmi64(Int64)
    case wasmi32(Int32)
    case wasmf32(Float32)
    case wasmf64(Float64)
    // Empty reference
    case refNull
    // function reference
    case refFunc(Int)

    // This is the case for imported Globals, we just need the type here.
    case imported(ILType)


    func toType() -> ILType {
        switch self {
        case .wasmi64:
            return .wasmi64
        case .wasmi32:
            return .wasmi32
        case .wasmf32:
            return .wasmf32
        case .wasmf64:
            return .wasmf64
        case .refNull:
            return .wasmExternRef
        case .imported(let type):
            assert(type.wasmGlobalType != nil)
            return type.wasmGlobalType!.valueType
        default:
            fatalError("Unimplemented / unhandled")
        }
    }

    func typeString() -> String {
        switch self {
        case .wasmi64(_):
            return "i64"
        case .wasmi32(_):
            return "i32"
        case .wasmf32(_):
            return "f32"
        case .wasmf64(_):
            return "f64"
        default:
            fatalError("Unimplemented / unhandled")
        }
    }

    func valueToString() -> String {
        switch self {
        case .wasmi64(let val):
            return "\(val)"
        case .wasmi32(let val):
            return "\(val)"
        case .wasmf32(let val):
            return "\(val)"
        case .wasmf64(let val):
            return "\(val)"
        default:
            fatalError("Unimplemented / unhandled")
        }
    }
    // Maybe add static random func?
}

final class WasmDefineGlobal: WasmOperation {
    override var opcode: Opcode { .wasmDefineGlobal(self) }

    let isMutable: Bool
    let wasmGlobal: WasmGlobal

    init(wasmGlobal: WasmGlobal, isMutable: Bool) {
        self.wasmGlobal = wasmGlobal
        self.isMutable = isMutable
        super.init(outputType: wasmGlobal.toType(), attributes: [.isPure, .isMutable], requiredContext: [.wasm])
    }

}

final class WasmDefineTable: WasmOperation {
    override var opcode: Opcode { .wasmDefineTable(self) }

    let tableType: ILType
    let minSize: Int
    let maxSize: Int?

    init(tableInfo: (ILType, Int, Int?)) {
        self.tableType = tableInfo.0
        self.minSize = tableInfo.1
        self.maxSize = tableInfo.2

        let tableType: ILType

        switch tableInfo.0 {
        case .wasmExternRef:
            tableType = .externRefTable
        case .wasmFuncRef:
            tableType  = .funcRefTable
        default:
            fatalError("Unknown table type")
        }

        super.init(outputType: tableType, attributes: [.isPure, .isMutable], requiredContext: [.wasm])
    }
}


// TODO: Wasm memory can be initialized in the data segment, theoretically one could initialize them with this instruction as well.
// Currently they are by default zero initialized and fuzzilli should then just store or load from there.
// Also note: https://webassembly.github.io/spec/core/syntax/modules.html#memories
// There may only be one memory defined or imported at any given time and any instructions uses this memory implicitly
final class WasmDefineMemory: WasmOperation {
    override var opcode: Opcode { .wasmDefineMemory(self) }

    let wasmMemory: ILType

    init(limits: Limits, isShared: Bool = false, isMemory64: Bool = false) {
        self.wasmMemory = .wasmMemory(limits: limits, isShared: isShared, isMemory64: isMemory64)
        super.init(outputType: self.wasmMemory, attributes: [.isPure, .isMutable], requiredContext: [.wasm])
    }
}

// TODO: Remove this operation.
final class WasmImportMemory: WasmOperation {
    override var opcode: Opcode { .wasmImportMemory(self) }

    let wasmMemory: ILType

    init(wasmMemory: ILType) {
        assert(wasmMemory.isWasmMemoryType)
        self.wasmMemory = wasmMemory
        super.init(inputTypes: [wasmMemory], outputType: wasmMemory, attributes: [.isPure, .isNotInputMutable], requiredContext: [.wasm])
    }
}

final class WasmImportTable: WasmOperation {
    override var opcode: Opcode { .wasmImportTable(self) }

    let tableType: ILType

    // TODO: This currently always imports an externRef table, but we should check what it actually is.
    // This should check against the input
    init(tableType: ILType) {
        self.tableType = tableType

        assert(tableType.Is(.object()))

        super.init(inputTypes: [tableType], outputType: convertTableTypeToWasmWorldType(tableType), attributes: [.isPure, .isNotInputMutable], requiredContext: [.wasm])
    }
}

// Converts to the wasm equivalent type
fileprivate func convertTableTypeToWasmWorldType(_ type: ILType) -> ILType {
    if type.Is(.object(ofGroup: "WasmTable.externref")) {
        return .externRefTable
    }
    if type.Is(.object(ofGroup: "WasmTable.funcref")) {
        return .funcRefTable
    }
    fatalError("unknown type import")
}

final class WasmImportGlobal: WasmOperation {
    override var opcode: Opcode { .wasmImportGlobal(self) }

    let wasmGlobal: ILType
    let isMutable: Bool

    // This is where we need a bit stricter typing. The type that flows into this operation needs to match with the given
    // valueType here, as otherwise we cannot do meaningful wasm programbuilding (is this true?)
    init(wasmGlobal: ILType) {
        self.wasmGlobal = wasmGlobal
        assert(wasmGlobal.isWasmGlobalType)
        let wasmGlobalType = wasmGlobal.wasmGlobalType!
        self.isMutable = wasmGlobalType.isMutable
        // We need to have this input variable here, such that we preserve the 'use' of the defined js global.
        super.init(inputTypes: [wasmGlobal], outputType: wasmGlobalType.valueType, attributes: [.isPure, .isNotInputMutable], requiredContext: [.wasm])
    }
}

final class WasmLoadGlobal: WasmOperation {
    override var opcode: Opcode { .wasmLoadGlobal(self) }

    let globalType: ILType

    // The first argument is the index into the global section.
    init(globalType: ILType) {
        self.globalType = globalType
        super.init(inputTypes: [globalType], outputType: globalType, attributes: [.isPure, .isNotInputMutable], requiredContext: [.wasmFunction])
    }
}

final class WasmStoreGlobal: WasmOperation {
    override var opcode: Opcode { .wasmStoreGlobal(self) }

    let globalType: ILType

    init(globalType: ILType) {
        self.globalType = globalType
        // Takes two inputs, one is the global reference the other is the value that is being stored in the global
        super.init(inputTypes: [globalType, globalType], attributes: [.isNotInputMutable], requiredContext: [.wasmFunction])
    }
}

final class WasmTableGet: WasmOperation {
    override var opcode: Opcode { .wasmTableGet(self) }

    init(tableType: ILType) {
        let outputType: ILType
        switch tableType {
        case .externRefTable:
            outputType = .wasmExternRef
        case .funcRefTable:
            outputType = .wasmFuncRef
        default:
            fatalError("Variable of invalid type passed to table operation")
        }
        // The input is the table reference and an index.
        super.init(inputTypes: [tableType, .wasmi32], outputType: outputType, attributes: [.isPure], requiredContext: [.wasmFunction])
    }
}

final class WasmTableSet: WasmOperation {
    override var opcode: Opcode { .wasmTableSet(self) }

    init(tableType: ILType) {
        let inputType: ILType
        switch tableType {
        case .externRefTable:
            inputType = .wasmExternRef
        case .funcRefTable:
            inputType = .wasmFuncRef
        default:
            fatalError("Variable of invalid type passed to table operation")
        }
        super.init(inputTypes: [tableType, .wasmi32, inputType], requiredContext: [.wasmFunction])
    }
}

final class WasmMemoryGet: WasmOperation {
    override var opcode: Opcode { .wasmMemoryGet(self) }

    let loadType: ILType
    let offset: Int

    init(loadType: ILType, offset: Int) {
        self.loadType = loadType
        self.offset = offset
        // Technically, Wasm currently does not require this variable, as we always pick the memory at "index 0" but we want it for proper dataflow in our IL.
        super.init(inputTypes: [.object(), .wasmi32], outputType: loadType, attributes: [.isMutable], requiredContext: [.wasmFunction])
    }
}

final class WasmMemorySet: WasmOperation {
    override var opcode: Opcode { .wasmMemorySet(self) }

    let storeType: ILType
    let offset: Int

    init(storeType: ILType, offset: Int) {
        self.storeType = storeType
        self.offset = offset
        super.init(inputTypes: [.object(), .wasmi32, storeType], attributes: [.isMutable], requiredContext: [.wasmFunction])
    }
}

final class WasmJsCall: WasmOperation {
    override var opcode: Opcode { .wasmJsCall(self) }

    let functionSignature: Signature

    init(signature: Signature) {
        self.functionSignature = signature
        var plainParams: [ILType] = []
        for param in signature.parameters {
            switch param {
            case .plain(let p):
                plainParams.append(p)
            case .rest(_), .opt(_):
                fatalError("We only expect to see .plain parameter types in wasm signatures")
            }
        }

        super.init(inputTypes: [.function()] + plainParams, outputType: functionSignature.outputType, requiredContext: [.wasmFunction])
    }
}

final class WasmBeginBlock: WasmOperation {
    override var opcode: Opcode { .wasmBeginBlock(self) }

    let signature: Signature

    init(with signature: Signature) {
        self.signature = signature

        // TODO(cffsmith): It is possible to just encode a valuetype that is a single return type.
        var parameterTypes: [ILType] = []
        for parameter in signature.parameters {
            switch parameter {
            case .plain(let typ):
                parameterTypes.append(typ)
            default:
                fatalError("Wrong type of parameter for a Wasm block")
            }
        }

        // TODO(cffsmith): This needs some extra handling as it will put some things onto the stack.
        super.init(outputType: signature.outputType, innerOutputTypes: [.label] + parameterTypes, attributes: [.isBlockStart, .propagatesSurroundingContext], requiredContext: [.wasmFunction], contextOpened: [.wasmBlock])
    }
}

final class WasmEndBlock: WasmOperation {
    override var opcode: Opcode { .wasmEndBlock(self) }

    init() {
        super.init(attributes: [.isPure, .isBlockEnd, .resumesSurroundingContext], requiredContext: [.wasmFunction, .wasmBlock])
    }
}

final class WasmBeginIf: WasmOperation {
    override var opcode: Opcode { .wasmBeginIf(self) }

    init() {
        super.init(inputTypes: [.wasmi32], attributes: [.isBlockStart, .propagatesSurroundingContext, .isNotInputMutable], requiredContext: [.wasmFunction], contextOpened: [.wasmBlock])
    }
}

final class WasmBeginElse: WasmOperation {
    override var opcode: Opcode { .wasmBeginElse(self) }

    init() {
        super.init(attributes: [.isBlockStart, .isBlockEnd, .propagatesSurroundingContext], requiredContext: [.wasmFunction], contextOpened: [.wasmBlock])
    }
}

final class WasmEndIf: WasmOperation {
    override var opcode: Opcode { .wasmEndIf(self) }

    init() {
        super.init(attributes: [.isBlockEnd], requiredContext: [.wasmBlock, .wasmFunction])
    }
}

final class WasmBeginLoop: WasmOperation {
    override var opcode: Opcode { .wasmBeginLoop(self) }

    let signature: Signature

    init(with signature: Signature) {
        self.signature = signature

        var parameterTypes: [ILType] = []
        for parameter in signature.parameters {
            switch parameter {
            case .plain(let typ):
                parameterTypes.append(typ)
            default:
                fatalError("Wrong type of parameter for a Wasm loop")
            }
        }

        super.init(outputType: signature.outputType, innerOutputTypes: [.label] + parameterTypes, attributes: [.isPure, .isBlockStart, .propagatesSurroundingContext], requiredContext: [.wasmFunction])
    }
}

final class WasmEndLoop: WasmOperation {
    override var opcode: Opcode { .wasmEndLoop(self) }

    init() {
        super.init(attributes: [.isPure, .isBlockEnd, .resumesSurroundingContext], requiredContext: [.wasmFunction])
    }
}

final class WasmBeginTry: WasmOperation {
    override var opcode: Opcode { .wasmBeginTry(self) }

    let signature: Signature

    init(with signature: Signature) {
        self.signature = signature

        var parameterTypes: [ILType] = []
        for parameter in signature.parameters {
            switch parameter {
            case .plain(let typ):
                parameterTypes.append(typ)
            default:
                fatalError("Wrong type of parameter for a Wasm try block")
            }
        }

        super.init(outputType: signature.outputType, innerOutputTypes: [.label] + parameterTypes, attributes: [.isPure, .isBlockStart, .propagatesSurroundingContext], requiredContext: [.wasmFunction])
    }
}

final class WasmEndTry: WasmOperation {
    override var opcode: Opcode { .wasmEndTry(self) }

    init() {
        super.init(attributes: [.isPure, .isBlockEnd, .resumesSurroundingContext], requiredContext: [.wasmFunction])
    }
}

final class WasmBranch: WasmOperation {
    override var opcode: Opcode { .wasmBranch(self) }

    init() {
        super.init(inputTypes: [.label], attributes: [.isPure], requiredContext: [.wasmFunction])

    }
}

final class WasmBranchIf: WasmOperation {
    override var opcode: Opcode { .wasmBranchIf(self) }

    init() {
        super.init(inputTypes: [.label, .wasmi32], attributes: [.isPure], requiredContext: [.wasmFunction])
    }

}

// TODO: make this comprehensive, currently only works for locals, or assumes every thing it reassigns to is a local.
// This should be doable in the lifter, where we can see what we reassign to.
final class WasmReassign: WasmOperation {
    override var opcode: Opcode { .wasmReassign(self) }

    let variableType: ILType

    init(variableType: ILType) {
        self.variableType = variableType
        super.init(inputTypes: [variableType, variableType], attributes: [.isNotInputMutable], requiredContext: [.wasmFunction])
    }
}

//
// Fuzzilli Wasm Instructions.
// These are internal, such that we have more information in the IL for mutation.
// They should all require at least .wasm.
//

final class BeginWasmFunction: WasmOperation {
    override var opcode: Opcode { .beginWasmFunction(self) }
    public let signature: Signature

    init(signature: Signature) {
        self.signature = signature

        var parameterTypes: [ILType] = []
        for parameter in signature.parameters {
            switch parameter {
            case .plain(let typ):
                parameterTypes.append(typ)
            default:
                fatalError("Wrong type of parameter for a Wasm function")
            }
        }
        super.init(innerOutputTypes: parameterTypes, attributes: [.isBlockStart], requiredContext: [.wasm], contextOpened: [.wasmFunction])
    }

    // Easy initializer for Protobuf deserialization
    init(parameterTypes: [ILType], returnType: ILType) {
        self.signature = Signature(expects: parameterTypes.map { .plain($0) }, returns: returnType)
        super.init(innerOutputTypes: parameterTypes, attributes: [.isBlockStart], requiredContext: [.wasm], contextOpened: [.wasmFunction])
    }
}

final class EndWasmFunction: WasmOperation {
    override var opcode: Opcode { .endWasmFunction(self) }
    init() {
        super.init(outputType: .wasmFuncRef, attributes: [.isBlockEnd], requiredContext: [.wasmFunction])
    }

}

/// This class is used to indicate nops in the wasm world, this makes handling of minimization much easier.
final class WasmNop: WasmOperation {
    override var opcode: Opcode { .wasmNop(self) }
    init(outputType: ILType, innerOutputTypes: [ILType]) {
        super.init(outputType: outputType, innerOutputTypes: innerOutputTypes, attributes: [.isInternal, .isNop], requiredContext: [.wasmFunction])
    }
}

final class ConstSimd128: WasmOperation {
    override var opcode: Opcode { .constSimd128(self) }
    let value: [UInt8]

    init(value: [UInt8]) {
        self.value = value;
        super.init(outputType: .wasmSimd128, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

// This array must be kept in sync with the Comparator Enum in operations.proto
public enum WasmSimd128CompareOpKind {
    case iKind(value: WasmIntegerCompareOpKind)
    case fKind(value: WasmFloatCompareOpKind)

    func toInt() -> Int {
        switch self {
        case .iKind(let value):
            return Int(value.rawValue)
        case .fKind(let value):
            return Int(value.rawValue)
        }
    }
}

extension WasmSimd128CompareOpKind: CustomStringConvertible {
    public var description: String {
        switch self {
        case .iKind(let value):
            return "\(value)"
        case .fKind(let value):
            return "\(value)"
        }
    }
}

public enum WasmSimd128Shape: UInt8, CaseIterable {
    case i8x16              = 0
    case i16x8              = 1
    case i32x4              = 2
    case i64x2              = 3
    case f32x4              = 4
    case f64x2              = 5

    func isFloat() -> Bool {
        switch self {
            case .i8x16,
                 .i16x8,
                 .i32x4,
                 .i64x2:
                return false
            case .f32x4,
                 .f64x2:
                return true
        }
    }
}

final class WasmSimd128Compare: WasmOperation {
    override var opcode: Opcode { .wasmSimd128Compare(self) }
    let shape: WasmSimd128Shape
    let compareOpKind: WasmSimd128CompareOpKind

    init(shape: WasmSimd128Shape, compareOpKind: WasmSimd128CompareOpKind) {
        self.shape = shape
        self.compareOpKind = compareOpKind
        super.init(inputTypes: [.wasmSimd128, .wasmSimd128], outputType: .wasmSimd128, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

public enum WasmSimd128IntegerUnOpKind: Int, CaseIterable {
    // The offsets are added to the a base value for each shape:
    // i8x16: 92 + offset
    // i16x8: 124 + offset
    // i32x4: 156 + offset
    // i64x2: 188 + offset
    case extadd_pairwise_i8x16_s = 0
    case extadd_pairwise_i8x16_u = 1
    case extadd_pairwise_i16x8_s = -34
    case extadd_pairwise_i16x8_u = -33
    case abs                     = 4
    case neg                     = 5
    // i8x16: popcnt, i16x8: q15mulr_sat_s
    case popcnt_q15mulr_sat_s    = 6
    case all_true                = 7
    case bitmask                 = 8
    case extend_low_s            = 11
    case extend_high_s           = 12
    case extend_low_u            = 13
    case extend_high_u           = 14

    func isValidForShape(shape: WasmSimd128Shape) -> Bool {
        if shape.isFloat() { return false }
        switch self {
        case .extadd_pairwise_i8x16_s:  return shape == .i16x8
        case .extadd_pairwise_i8x16_u:  return shape == .i16x8
        case .extadd_pairwise_i16x8_s:  return shape == .i32x4
        case .extadd_pairwise_i16x8_u:  return shape == .i32x4
        case .abs:                      return true
        case .neg:                      return true
        case .popcnt_q15mulr_sat_s:     return shape == .i8x16 || shape == .i16x8
        case .all_true:                 return true
        case .bitmask:                  return true
        case .extend_low_s:             return shape != .i8x16
        case .extend_high_s:            return shape != .i8x16
        case .extend_low_u:             return shape != .i8x16
        case .extend_high_u:            return shape != .i8x16
        }
    }
}

final class WasmSimd128IntegerUnOp: WasmOperation {
    override var opcode: Opcode { .wasmSimd128IntegerUnOp(self) }
    let shape: WasmSimd128Shape
    let unOpKind: WasmSimd128IntegerUnOpKind

    init(shape: WasmSimd128Shape, unOpKind: WasmSimd128IntegerUnOpKind) {
        self.shape = shape
        self.unOpKind = unOpKind
        super.init(inputTypes: [.wasmSimd128], outputType: .wasmSimd128, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

public enum WasmSimd128IntegerBinOpKind: Int, CaseIterable {
    // The offsets are added to the a base value for each shape:
    // i8x16: 92 + offset
    // i16x8: 124 + offset
    // i32x4: 156 + offset
    // i64x2: 188 + offset
    case narrow_s      = 9
    case narrow_u      = 10

    case shl           = 15
    case shr_s         = 16
    case shr_u         = 17
    case add           = 18
    case add_sat_s     = 19
    case add_sat_u     = 20
    case sub           = 21
    case sub_sat_s     = 22
    case sub_sat_u     = 23

    case mul           = 25
    case min_s         = 26
    case min_u         = 27
    case max_s         = 28
    case max_u         = 29
    case dot_i16x8_s   = 30
    case avgr_u        = 31
    case extmul_low_s  = 32
    case extmul_high_s = 33
    case extmul_low_u  = 34
    case extmul_high_u = 35

    func isValidForShape(shape: WasmSimd128Shape) -> Bool {
        if shape.isFloat() { return false }
        switch self {
        case .narrow_s:      return shape == .i8x16 || shape == .i16x8
        case .narrow_u:      return shape == .i8x16 || shape == .i16x8
        case .shl:           return true
        case .shr_s:         return true
        case .shr_u:         return true
        case .add:           return true
        case .add_sat_s:     return shape == .i8x16 || shape == .i16x8
        case .add_sat_u:     return shape == .i8x16 || shape == .i16x8
        case .sub:           return true
        case .sub_sat_s:     return shape == .i8x16 || shape == .i16x8
        case .sub_sat_u:     return shape == .i8x16 || shape == .i16x8
        case .mul:           return shape != .i8x16
        case .min_s:         return shape != .i64x2
        case .min_u:         return shape != .i64x2
        case .max_s:         return shape != .i64x2
        case .max_u:         return shape != .i64x2
        case .dot_i16x8_s:   return shape == .i32x4
        case .avgr_u:        return shape == .i8x16 || shape == .i16x8
        case .extmul_low_s:  return shape != .i8x16
        case .extmul_high_s: return shape != .i8x16
        case .extmul_low_u:  return shape != .i8x16
        case .extmul_high_u: return shape != .i8x16
        }
    }
}

final class WasmSimd128IntegerBinOp: WasmOperation {
    override var opcode: Opcode { .wasmSimd128IntegerBinOp(self) }
    let shape: WasmSimd128Shape
    let binOpKind: WasmSimd128IntegerBinOpKind

    init(shape: WasmSimd128Shape, binOpKind: WasmSimd128IntegerBinOpKind) {
        self.shape = shape
        self.binOpKind = binOpKind
        super.init(inputTypes: [.wasmSimd128, .wasmSimd128], outputType: .wasmSimd128, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

// TODO: Generalize to other shapes.
final class WasmI64x2Splat: WasmOperation {
    override var opcode: Opcode { .wasmI64x2Splat(self) }
    init() {
        super.init(inputTypes: [.wasmi64], outputType: .wasmSimd128, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

// TODO: Generalize to other shapes.
final class WasmI64x2ExtractLane: WasmOperation {
  override var opcode: Opcode { .wasmI64x2ExtractLane(self) }
  let lane: Int

  init(lane: Int) {
    self.lane = lane;
    super.init(inputTypes: [.wasmSimd128 ], outputType: .wasmi64, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
  }
}

final class WasmI64x2LoadSplat: WasmOperation {
    override var opcode: Opcode { .wasmI64x2LoadSplat(self) }
    let offset: Int;
    init(offset: Int) {
        self.offset = offset;
        super.init(inputTypes: [.object()], outputType: .wasmSimd128, attributes: [.isPure, .isMutable], requiredContext: [.wasmFunction])
    }
}

