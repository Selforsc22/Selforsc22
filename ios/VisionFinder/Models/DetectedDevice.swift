import Foundation
import CoreBluetooth

/// Represents a detected Bluetooth device
struct DetectedDevice: Identifiable, Equatable {
    let id: UUID
    let peripheralIdentifier: UUID
    var name: String?
    var rssi: Int
    var manufacturerData: Data?
    var manufacturerID: UInt16?
    var serviceUUIDs: [CBUUID]
    var firstSeen: Date
    var lastSeen: Date
    var isThreat: Bool
    var threatLevel: ThreatLevel
    var matchedSignature: KnownManufacturerID?

    init(
        peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi: NSNumber
    ) {
        self.id = UUID()
        self.peripheralIdentifier = peripheral.identifier
        self.name = peripheral.name ?? advertisementData[CBAdvertisementDataLocalNameKey] as? String
        self.rssi = rssi.intValue
        self.firstSeen = Date()
        self.lastSeen = Date()
        self.isThreat = false
        self.threatLevel = .none
        self.serviceUUIDs = []

        // Extract manufacturer data
        if let mfrData = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
           mfrData.count >= 2 {
            self.manufacturerData = mfrData
            // Manufacturer ID is first 2 bytes (little-endian)
            self.manufacturerID = UInt16(mfrData[0]) | (UInt16(mfrData[1]) << 8)
        }

        // Extract service UUIDs
        if let uuids = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
            self.serviceUUIDs = uuids
        }

        // Check for threats
        checkForThreat()
    }

    mutating func update(advertisementData: [String: Any], rssi: NSNumber) {
        self.rssi = rssi.intValue
        self.lastSeen = Date()

        if let newName = advertisementData[CBAdvertisementDataLocalNameKey] as? String {
            self.name = newName
        }

        if let mfrData = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
           mfrData.count >= 2 {
            self.manufacturerData = mfrData
            self.manufacturerID = UInt16(mfrData[0]) | (UInt16(mfrData[1]) << 8)
        }

        checkForThreat()
    }

    private mutating func checkForThreat() {
        // Check manufacturer ID first (most reliable)
        if let mfrID = manufacturerID,
           let known = KnownManufacturerID(rawValue: mfrID) {
            self.isThreat = true
            self.threatLevel = known.threatLevel
            self.matchedSignature = known
            return
        }

        // Check service UUIDs (HeyCyan)
        let heyCyanUUID = CBUUID(string: heyCyanServiceUUID)
        if serviceUUIDs.contains(heyCyanUUID) {
            self.isThreat = true
            self.threatLevel = .high
            self.matchedSignature = .heycyanJieli
            return
        }

        // Check name patterns
        if let deviceName = name?.lowercased() {
            let threatPatterns = [
                "ray-ban", "rayban", "spectacles", "meta", "gopro",
                "hero", "glass", "vuzix", "insta360", "heycyan"
            ]
            for pattern in threatPatterns {
                if deviceName.contains(pattern) {
                    self.isThreat = true
                    self.threatLevel = .medium
                    return
                }
            }
        }
    }

    var distanceDescription: String {
        switch rssi {
        case -50...: return "Very close (<1m)"
        case -60 ..< -50: return "Close (1-3m)"
        case -70 ..< -60: return "Nearby (3-7m)"
        case -80 ..< -70: return "Medium (7-15m)"
        default: return "Far (>15m)"
        }
    }

    var manufacturerIDHex: String? {
        guard let id = manufacturerID else { return nil }
        return String(format: "0x%04X", id)
    }

    static func == (lhs: DetectedDevice, rhs: DetectedDevice) -> Bool {
        lhs.peripheralIdentifier == rhs.peripheralIdentifier
    }
}
