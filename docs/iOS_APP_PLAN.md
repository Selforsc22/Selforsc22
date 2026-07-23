# VisionFinder iOS App Development Plan

## Overview

Native iOS app for detecting Bluetooth-enabled recording devices using Core Bluetooth framework.

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Swift 5.9+ |
| UI Framework | SwiftUI |
| Bluetooth | Core Bluetooth |
| Architecture | MVVM + Combine |
| Min iOS Version | iOS 16.0 |
| Local Storage | SwiftData / Core Data |
| Notifications | UserNotifications |
| Background | Background Tasks + BLE Background Mode |

## Project Structure

```
VisionFinder-iOS/
├── VisionFinder.xcodeproj
├── VisionFinder/
│   ├── App/
│   │   ├── VisionFinderApp.swift
│   │   └── AppDelegate.swift
│   ├── Models/
│   │   ├── DeviceSignature.swift
│   │   ├── DetectedDevice.swift
│   │   ├── ThreatLevel.swift
│   │   └── ScanSettings.swift
│   ├── Services/
│   │   ├── BluetoothScanner.swift
│   │   ├── ThreatDetector.swift
│   │   ├── NotificationService.swift
│   │   └── PersistenceService.swift
│   ├── ViewModels/
│   │   ├── ScannerViewModel.swift
│   │   ├── SettingsViewModel.swift
│   │   └── HistoryViewModel.swift
│   ├── Views/
│   │   ├── MainTabView.swift
│   │   ├── ScannerView.swift
│   │   ├── DeviceListView.swift
│   │   ├── DeviceDetailView.swift
│   │   ├── SettingsView.swift
│   │   ├── HistoryView.swift
│   │   └── Components/
│   │       ├── DeviceCard.swift
│   │       ├── ThreatBadge.swift
│   │       ├── CanaryIndicator.swift
│   │       └── RSSIGauge.swift
│   └── Resources/
│       ├── Assets.xcassets
│       ├── DeviceSignatures.json
│       └── Localizable.strings
├── VisionFinderTests/
└── VisionFinderUITests/
```

## Phase 1: Core Bluetooth Scanner (Week 1-2)

### 1.1 Bluetooth Manager
```swift
// BluetoothScanner.swift
import CoreBluetooth
import Combine

class BluetoothScanner: NSObject, ObservableObject {
    @Published var discoveredDevices: [DetectedDevice] = []
    @Published var isScanning = false
    @Published var canaryStatus: Bool = true
    
    private var centralManager: CBCentralManager!
    private let threatDetector: ThreatDetector
    
    // Manufacturer IDs to detect
    static let threatManufacturerIDs: Set<UInt16> = [
        0x01AB,  // Meta Platforms
        0x058E,  // Meta Technologies
        0x0D53,  // Luxottica
        0x03C2,  // Snap Inc.
        0x05D6,  // HeyCyan/Jieli
        0x00E0,  // Google
        0x028E,  // GoPro
    ]
    
    func startScanning()
    func stopScanning()
    func checkForThreats(_ device: CBPeripheral, _ advertisementData: [String: Any])
}
```

### 1.2 Device Detection Models
```swift
// DetectedDevice.swift
struct DetectedDevice: Identifiable, Codable {
    let id: UUID
    let identifier: String
    var name: String?
    var rssi: Int
    var manufacturerData: Data?
    var manufacturerID: UInt16?
    var serviceUUIDs: [CBUUID]
    var firstSeen: Date
    var lastSeen: Date
    var isThreat: Bool
    var threatLevel: ThreatLevel
    var matchedSignature: DeviceSignature?
}

enum ThreatLevel: String, Codable {
    case high, medium, low, none
}
```

### 1.3 Info.plist Permissions
```xml
<key>NSBluetoothAlwaysUsageDescription</key>
<string>VisionFinder needs Bluetooth to detect nearby recording devices</string>
<key>UIBackgroundModes</key>
<array>
    <string>bluetooth-central</string>
</array>
```

## Phase 2: UI Implementation (Week 2-3)

### 2.1 Main Scanner View
- Real-time device list with RSSI indicators
- Threat highlighting with color coding
- Pull-to-refresh for manual scan trigger
- Canary status indicator (green/red circle)

### 2.2 Device Detail View
- Device name, address, RSSI
- Manufacturer ID (hex format)
- Distance estimation
- Threat information
- Detection history

### 2.3 Settings View
- RSSI threshold slider (-50 to -90 dBm)
- Notification cooldown picker
- Custom manufacturer ID input
- Background scanning toggle
- Debug mode toggle

### 2.4 History View
- Chronological detection log
- Filter by threat level
- Export functionality

## Phase 3: Notifications & Background (Week 3-4)

### 3.1 Local Notifications
```swift
// NotificationService.swift
class NotificationService {
    func requestPermission()
    func sendThreatAlert(device: DetectedDevice)
    func sendCanaryStatusChange(allClear: Bool)
}
```

### 3.2 Background Scanning
- Use `CBCentralManager` background mode
- Register for `bluetooth-central` background mode
- Handle state restoration
- Optimize for battery life

### 3.3 Haptic Feedback
```swift
// Different patterns for threat levels
func triggerHaptic(for threatLevel: ThreatLevel) {
    switch threatLevel {
    case .high:
        UINotificationFeedbackGenerator().notificationOccurred(.error)
    case .medium:
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
    default:
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }
}
```

## Phase 4: Data Persistence (Week 4)

### 4.1 SwiftData Models
```swift
@Model
class PersistedDevice {
    var identifier: String
    var name: String?
    var firstSeen: Date
    var lastSeen: Date
    var timesSeen: Int
    var isThreat: Bool
    var matchedSignature: String?
}

@Model
class DetectionEvent {
    var deviceIdentifier: String
    var timestamp: Date
    var rssi: Int
    var manufacturerID: UInt16?
}
```

### 4.2 Statistics
- Total devices seen
- Threats detected
- Detection heatmaps
- Dwell time tracking

## Phase 5: Polish & Testing (Week 5)

### 5.1 Unit Tests
- BluetoothScanner tests
- ThreatDetector tests
- Notification tests

### 5.2 UI Tests
- Scanner flow
- Settings changes
- Device detail navigation

### 5.3 Accessibility
- VoiceOver support
- Dynamic Type
- High contrast mode

## iOS Limitations & Workarounds

| Limitation | Workaround |
|------------|------------|
| No continuous background scanning | Use BLE state restoration, scan on region enter |
| Limited background processing | Use BGTaskScheduler for periodic checks |
| No MAC address access | Use peripheral identifier (changes between app installs) |
| Scan throttling in background | Optimize scan intervals, use specific service UUIDs |

## App Store Considerations

### Privacy Requirements
- Privacy Policy URL required
- Data usage disclosure
- Bluetooth permission justification

### Review Guidelines
- Must clearly explain Bluetooth usage
- Cannot claim to "detect all" recording devices
- Disclaimer about false positives/negatives

## Estimated Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | 2 weeks | Core scanner working |
| Phase 2 | 1 week | UI complete |
| Phase 3 | 1 week | Notifications working |
| Phase 4 | 1 week | Persistence complete |
| Phase 5 | 1 week | Testing & polish |
| **Total** | **6 weeks** | App Store ready |

## Dependencies

```swift
// Package.swift or SPM
dependencies: [
    .package(url: "https://github.com/pointfreeco/swift-composable-architecture", from: "1.0.0"),
    // Optional: for more complex state management
]
```

## Next Steps

1. Create Xcode project with SwiftUI template
2. Set up Core Bluetooth permissions
3. Implement BluetoothScanner service
4. Build scanner UI
5. Add notification support
6. Implement persistence
7. Write tests
8. Submit to App Store
