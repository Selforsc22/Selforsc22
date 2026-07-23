import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var scanner: BluetoothScanner
    @State private var customIDInput = ""

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Detection Settings")) {
                    VStack(alignment: .leading) {
                        Text("RSSI Threshold: \(scanner.rssiThreshold) dBm")
                        Slider(
                            value: Binding(
                                get: { Double(scanner.rssiThreshold) },
                                set: { scanner.rssiThreshold = Int($0) }
                            ),
                            in: -90...(-50),
                            step: 5
                        )
                        Text("Closer devices have higher RSSI values")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    VStack(alignment: .leading) {
                        Text("Notification Cooldown: \(Int(scanner.notificationCooldown))s")
                        Slider(
                            value: $scanner.notificationCooldown,
                            in: 5...60,
                            step: 5
                        )
                        Text("Time between alerts for the same device")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Section(header: Text("Custom Manufacturer IDs")) {
                    HStack {
                        TextField("Enter hex ID (e.g., 0x1234)", text: $customIDInput)
                            .textFieldStyle(.roundedBorder)
                            .autocapitalization(.none)

                        Button("Add") {
                            addCustomID()
                        }
                        .disabled(customIDInput.isEmpty)
                    }

                    if !scanner.customManufacturerIDs.isEmpty {
                        ForEach(Array(scanner.customManufacturerIDs), id: \.self) { id in
                            HStack {
                                Text(String(format: "0x%04X", id))
                                    .font(.monospaced(.body)())
                                Spacer()
                                Button(action: {
                                    scanner.customManufacturerIDs.remove(id)
                                }) {
                                    Image(systemName: "trash")
                                        .foregroundColor(.red)
                                }
                            }
                        }
                    } else {
                        Text("No custom IDs configured")
                            .foregroundColor(.secondary)
                    }
                }

                Section(header: Text("Known Threat IDs")) {
                    ForEach(KnownManufacturerID.allCases, id: \.rawValue) { id in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(id.name)
                                    .font(.subheadline)
                                Text(String(format: "0x%04X", id.rawValue))
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            ThreatBadge(level: id.threatLevel)
                        }
                    }
                }

                Section(header: Text("About")) {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0")
                            .foregroundColor(.secondary)
                    }
                    Link("View on GitHub", destination: URL(string: "https://github.com/Selforsc22/VisionFinder")!)
                }
            }
            .navigationTitle("Settings")
        }
    }

    private func addCustomID() {
        var input = customIDInput.trimmingCharacters(in: .whitespaces)

        // Remove 0x prefix if present
        if input.lowercased().hasPrefix("0x") {
            input = String(input.dropFirst(2))
        }

        // Parse as hex
        if let value = UInt16(input, radix: 16) {
            scanner.addCustomManufacturerID(value)
            customIDInput = ""
        }
    }
}

struct ThreatBadge: View {
    let level: ThreatLevel

    var body: some View {
        Text(level.rawValue.uppercased())
            .font(.caption2)
            .fontWeight(.bold)
            .foregroundColor(.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(badgeColor)
            .cornerRadius(4)
    }

    private var badgeColor: Color {
        switch level {
        case .high: return .red
        case .medium: return .orange
        case .low: return .green
        case .none: return .gray
        }
    }
}

#Preview {
    SettingsView()
        .environmentObject(BluetoothScanner())
}
