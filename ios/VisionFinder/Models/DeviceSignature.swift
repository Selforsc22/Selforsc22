import Foundation

/// Known recording device signature for detection
struct DeviceSignature: Codable, Identifiable {
    let id: String
    let name: String
    let manufacturer: String
    let type: DeviceType
    let hasCamera: Bool
    let hasMicrophone: Bool
    let threatLevel: ThreatLevel
    let namePatterns: [String]
    let manufacturerPrefixes: [String]
    let bleManufacturerIDs: [UInt16]
    let serviceUUIDs: [String]

    enum DeviceType: String, Codable {
        case smartGlasses = "smart_glasses"
        case actionCamera = "action_camera"
        case wearableCamera = "wearable_camera"
        case securityCamera = "security_camera"
        case unknown
    }
}

enum ThreatLevel: String, Codable, CaseIterable {
    case high
    case medium
    case low
    case none

    var color: String {
        switch self {
        case .high: return "#e63757"
        case .medium: return "#f6c343"
        case .low: return "#28a745"
        case .none: return "#6c757d"
        }
    }

    var description: String {
        switch self {
        case .high: return "Camera detected - can record video"
        case .medium: return "Microphone only - can record audio"
        case .low: return "Minimal recording capability"
        case .none: return "Not a recording device"
        }
    }
}

/// Verified BLE Manufacturer IDs from Bluetooth SIG
enum KnownManufacturerID: UInt16, CaseIterable {
    case metaPlatforms = 0x01AB       // 427
    case metaTechnologies = 0x058E    // 1422
    case luxottica = 0x0D53           // 3411
    case snapInc = 0x03C2             // 962
    case heycyanJieli = 0x05D6        // 1494
    case amazon = 0x00AB              // 171
    case google = 0x00E0              // 224
    case gopro = 0x028E               // 654
    case dji = 0x02C2                 // 706
    case vuzix = 0x0485               // 1157
    case xiaomi = 0x0157              // 343
    case huawei = 0x027D              // 637
    case bose = 0x009E                // 158

    var name: String {
        switch self {
        case .metaPlatforms, .metaTechnologies, .luxottica:
            return "Meta Smart Glasses (Ray-Ban)"
        case .snapInc:
            return "Snapchat Spectacles"
        case .heycyanJieli:
            return "HeyCyan SDK Smart Glasses"
        case .amazon:
            return "Amazon Echo Frames"
        case .google:
            return "Google Glass"
        case .gopro:
            return "GoPro Camera"
        case .dji:
            return "DJI Action Camera"
        case .vuzix:
            return "Vuzix Smart Glasses"
        case .xiaomi:
            return "Xiaomi Smart Glasses"
        case .huawei:
            return "Huawei Eyewear"
        case .bose:
            return "Bose Frames"
        }
    }

    var hasCamera: Bool {
        switch self {
        case .amazon, .huawei, .bose:
            return false
        default:
            return true
        }
    }

    var threatLevel: ThreatLevel {
        switch self {
        case .metaPlatforms, .metaTechnologies, .luxottica,
             .snapInc, .heycyanJieli, .google, .vuzix, .xiaomi:
            return .high
        case .gopro, .dji, .amazon, .huawei:
            return .medium
        case .bose:
            return .low
        }
    }

    static var allThreatIDs: Set<UInt16> {
        Set(allCases.map { $0.rawValue })
    }
}

/// HeyCyan SDK Service UUID - used by many smart glasses
let heyCyanServiceUUID = "7905FFF0-B5CE-4E99-A40F-4B1E122D00D0"
