import SwiftUI

struct HistoryView: View {
    @EnvironmentObject var scanner: BluetoothScanner
    @State private var showThreatsOnly = false

    var body: some View {
        NavigationView {
            VStack {
                // Filter Toggle
                Picker("Filter", selection: $showThreatsOnly) {
                    Text("All Devices").tag(false)
                    Text("Threats Only").tag(true)
                }
                .pickerStyle(.segmented)
                .padding()

                if filteredDevices.isEmpty {
                    EmptyHistoryView()
                } else {
                    List(filteredDevices) { device in
                        HistoryRow(device: device)
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("History")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button(action: exportHistory) {
                            Label("Export", systemImage: "square.and.arrow.up")
                        }
                        Button(role: .destructive, action: clearHistory) {
                            Label("Clear History", systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
        }
    }

    private var filteredDevices: [DetectedDevice] {
        if showThreatsOnly {
            return scanner.discoveredDevices.filter { $0.isThreat }
        }
        return scanner.discoveredDevices
    }

    private func exportHistory() {
        // Export functionality
        let text = filteredDevices.map { device in
            "\(device.name ?? "Unknown"),\(device.peripheralIdentifier),\(device.rssi),\(device.isThreat)"
        }.joined(separator: "\n")

        let header = "Name,Identifier,RSSI,IsThreat\n"
        UIPasteboard.general.string = header + text
    }

    private func clearHistory() {
        scanner.clearDevices()
    }
}

struct HistoryRow: View {
    let device: DetectedDevice

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(device.name ?? "Unknown Device")
                    .font(.headline)

                Spacer()

                if device.isThreat {
                    ThreatBadge(level: device.threatLevel)
                }
            }

            HStack {
                Label(device.distanceDescription, systemImage: "wifi")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Text(device.lastSeen, style: .relative)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if let signature = device.matchedSignature {
                HStack {
                    Image(systemName: signature.hasCamera ? "video.fill" : "mic.fill")
                        .foregroundColor(.red)
                    Text(signature.name)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct EmptyHistoryView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "clock")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text("No detection history")
                .foregroundColor(.secondary)

            Text("Detected devices will appear here")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

#Preview {
    HistoryView()
        .environmentObject(BluetoothScanner())
}
