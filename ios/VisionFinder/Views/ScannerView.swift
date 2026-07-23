import SwiftUI

struct ScannerView: View {
    @EnvironmentObject var scanner: BluetoothScanner

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Canary Status Banner
                CanaryBanner(allClear: scanner.canaryStatus)

                // Stats Row
                StatsRow(
                    deviceCount: scanner.discoveredDevices.count,
                    threatCount: scanner.discoveredDevices.filter { $0.isThreat }.count
                )

                // Device List
                List {
                    if scanner.discoveredDevices.isEmpty {
                        EmptyStateView(isScanning: scanner.isScanning)
                    } else {
                        ForEach(sortedDevices) { device in
                            DeviceRow(device: device)
                        }
                    }
                }
                .listStyle(.plain)
                .refreshable {
                    scanner.clearDevices()
                    scanner.startScanning()
                }

                // Scan Button
                ScanButton(
                    isScanning: scanner.isScanning,
                    onTap: toggleScanning
                )
            }
            .navigationTitle("VisionFinder")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: scanner.clearDevices) {
                        Image(systemName: "trash")
                    }
                    .disabled(!scanner.isScanning && scanner.discoveredDevices.isEmpty)
                }
            }
        }
    }

    private var sortedDevices: [DetectedDevice] {
        scanner.discoveredDevices.sorted { lhs, rhs in
            if lhs.isThreat != rhs.isThreat {
                return lhs.isThreat
            }
            return lhs.rssi > rhs.rssi
        }
    }

    private func toggleScanning() {
        if scanner.isScanning {
            scanner.stopScanning()
        } else {
            scanner.startScanning()
        }
    }
}

// MARK: - Subviews

struct CanaryBanner: View {
    let allClear: Bool

    var body: some View {
        HStack {
            Circle()
                .fill(allClear ? Color.green : Color.red)
                .frame(width: 12, height: 12)

            Text(allClear ? "ALL CLEAR" : "THREAT NEARBY")
                .font(.headline)
                .foregroundColor(allClear ? .green : .red)

            Spacer()
        }
        .padding()
        .background(allClear ? Color.green.opacity(0.1) : Color.red.opacity(0.1))
    }
}

struct StatsRow: View {
    let deviceCount: Int
    let threatCount: Int

    var body: some View {
        HStack(spacing: 20) {
            StatCard(title: "Devices", value: "\(deviceCount)", color: .blue)
            StatCard(title: "Threats", value: "\(threatCount)", color: .red)
        }
        .padding()
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack {
            Text(value)
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(color)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct DeviceRow: View {
    let device: DetectedDevice

    var body: some View {
        HStack {
            // Threat indicator
            Circle()
                .fill(threatColor)
                .frame(width: 10, height: 10)

            VStack(alignment: .leading, spacing: 4) {
                Text(device.name ?? "Unknown Device")
                    .font(.headline)

                HStack {
                    Text(device.distanceDescription)
                        .font(.caption)
                        .foregroundColor(.secondary)

                    if let mfrID = device.manufacturerIDHex {
                        Text("• \(mfrID)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if device.isThreat, let signature = device.matchedSignature {
                    Text(signature.name)
                        .font(.caption)
                        .foregroundColor(.red)
                        .fontWeight(.medium)
                }
            }

            Spacer()

            // RSSI
            VStack(alignment: .trailing) {
                Text("\(device.rssi)")
                    .font(.title3)
                    .fontWeight(.semibold)
                Text("dBm")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 8)
        .background(device.isThreat ? Color.red.opacity(0.05) : Color.clear)
    }

    private var threatColor: Color {
        switch device.threatLevel {
        case .high: return .red
        case .medium: return .orange
        case .low: return .green
        case .none: return .gray
        }
    }
}

struct ScanButton: View {
    let isScanning: Bool
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack {
                Image(systemName: isScanning ? "stop.fill" : "play.fill")
                Text(isScanning ? "Stop Scanning" : "Start Scanning")
            }
            .font(.headline)
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding()
            .background(isScanning ? Color.red : Color.blue)
            .cornerRadius(12)
        }
        .padding()
    }
}

struct EmptyStateView: View {
    let isScanning: Bool

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: isScanning ? "antenna.radiowaves.left.and.right" : "bluetooth")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text(isScanning ? "Scanning for devices..." : "Tap Start Scanning to detect nearby devices")
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 60)
    }
}

#Preview {
    ScannerView()
        .environmentObject(BluetoothScanner())
}
