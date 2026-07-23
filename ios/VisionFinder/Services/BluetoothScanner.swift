import Foundation
import CoreBluetooth
import Combine
import UserNotifications

/// Main Bluetooth scanner service for detecting recording devices
class BluetoothScanner: NSObject, ObservableObject {
    // MARK: - Published Properties

    @Published var discoveredDevices: [DetectedDevice] = []
    @Published var isScanning = false
    @Published var canaryStatus = true  // true = all clear
    @Published var bluetoothState: CBManagerState = .unknown
    @Published var lastThreatDetected: DetectedDevice?

    // MARK: - Settings

    @Published var rssiThreshold: Int = -75
    @Published var notificationCooldown: TimeInterval = 10.0
    @Published var customManufacturerIDs: Set<UInt16> = []

    // MARK: - Private Properties

    private var centralManager: CBCentralManager!
    private var lastAlertTimes: [UUID: Date] = [:]
    private let notificationService = NotificationService()
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Initialization

    override init() {
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: nil, options: [
            CBCentralManagerOptionRestoreIdentifierKey: "VisionFinderScanner"
        ])

        // Request notification permissions
        notificationService.requestPermission()
    }

    // MARK: - Public Methods

    func startScanning() {
        guard centralManager.state == .poweredOn else {
            print("Bluetooth not ready: \(centralManager.state.rawValue)")
            return
        }

        isScanning = true
        discoveredDevices.removeAll()
        canaryStatus = true

        // Scan for all devices (nil = no service filter)
        centralManager.scanForPeripherals(
            withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )

        print("Started scanning for devices...")
    }

    func stopScanning() {
        centralManager.stopScan()
        isScanning = false
        print("Stopped scanning")
    }

    func addCustomManufacturerID(_ id: UInt16) {
        customManufacturerIDs.insert(id)
        print("Added custom manufacturer ID: \(String(format: "0x%04X", id))")
    }

    func clearDevices() {
        discoveredDevices.removeAll()
        canaryStatus = true
    }

    // MARK: - Private Methods

    private func processDiscoveredDevice(
        _ peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi: NSNumber
    ) {
        // Find existing device or create new
        if let index = discoveredDevices.firstIndex(where: { $0.peripheralIdentifier == peripheral.identifier }) {
            discoveredDevices[index].update(advertisementData: advertisementData, rssi: rssi)
            checkAndAlert(device: discoveredDevices[index])
        } else {
            var newDevice = DetectedDevice(
                peripheral: peripheral,
                advertisementData: advertisementData,
                rssi: rssi
            )

            // Check custom manufacturer IDs
            if let mfrID = newDevice.manufacturerID,
               customManufacturerIDs.contains(mfrID) {
                newDevice.isThreat = true
                newDevice.threatLevel = .high
            }

            discoveredDevices.append(newDevice)
            checkAndAlert(device: newDevice)
        }
    }

    private func checkAndAlert(device: DetectedDevice) {
        guard device.isThreat else { return }
        guard device.rssi >= rssiThreshold else { return }

        // Update canary status
        canaryStatus = false

        // Check cooldown
        if let lastAlert = lastAlertTimes[device.peripheralIdentifier] {
            guard Date().timeIntervalSince(lastAlert) >= notificationCooldown else {
                return
            }
        }

        // Record alert time
        lastAlertTimes[device.peripheralIdentifier] = Date()
        lastThreatDetected = device

        // Send notification
        notificationService.sendThreatAlert(device: device)

        // Haptic feedback
        triggerHaptic(for: device.threatLevel)

        print("THREAT DETECTED: \(device.matchedSignature?.name ?? "Unknown") at RSSI \(device.rssi)")
    }

    private func triggerHaptic(for threatLevel: ThreatLevel) {
        #if os(iOS)
        switch threatLevel {
        case .high:
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.error)
        case .medium:
            let generator = UINotificationFeedbackGenerator()
            generator.notificationOccurred(.warning)
        default:
            let generator = UIImpactFeedbackGenerator(style: .light)
            generator.impactOccurred()
        }
        #endif
    }
}

// MARK: - CBCentralManagerDelegate

extension BluetoothScanner: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        bluetoothState = central.state

        switch central.state {
        case .poweredOn:
            print("Bluetooth is powered on")
            if isScanning {
                startScanning()
            }
        case .poweredOff:
            print("Bluetooth is powered off")
            isScanning = false
        case .unauthorized:
            print("Bluetooth unauthorized")
        case .unsupported:
            print("Bluetooth unsupported")
        default:
            print("Bluetooth state: \(central.state.rawValue)")
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        processDiscoveredDevice(peripheral, advertisementData: advertisementData, rssi: RSSI)
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        // Handle state restoration for background mode
        print("Restoring Bluetooth state...")
        if let peripherals = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] {
            print("Restored \(peripherals.count) peripherals")
        }
    }
}

// MARK: - Notification Service

class NotificationService {
    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("Notification permission granted")
            } else if let error = error {
                print("Notification permission error: \(error)")
            }
        }
    }

    func sendThreatAlert(device: DetectedDevice) {
        let content = UNMutableNotificationContent()
        content.title = "⚠️ Recording Device Detected!"
        content.body = "\(device.matchedSignature?.name ?? "Unknown device") detected nearby (\(device.distanceDescription))"
        content.sound = .default
        content.categoryIdentifier = "THREAT_ALERT"

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request)
    }
}
