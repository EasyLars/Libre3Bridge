/*  ContentView.swift
 *  Part of Libre3Bridge – FreeStyle Libre 3 direct BLE connection for iOS
 *
 *  Copyright (C) 2024 Lars Oeljeschläger & Lars
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  Main UI: glucose display, connection status, KDF result table, and
 *  scrollable log.  The log can be copied to clipboard for sharing test results.
 */

import SwiftUI

struct ContentView: View {
    @StateObject private var manager = Libre3Manager()
    @State private var showLog = true

    var body: some View {
        NavigationStack {
            ZStack(alignment: .top) {
                backgroundGradient.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 16) {
                        glucoseCard
                        statusCard
                        if !manager.kdfResults.isEmpty { kdfCard }
                        logCard
                    }
                    .padding()
                }
            }
            .navigationTitle("Libre 3 Bridge")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: copyLog) {
                        Image(systemName: "doc.on.doc")
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    connectButton
                }
            }
        }
    }

    // MARK: - Background

    private var backgroundGradient: some View {
        LinearGradient(
            colors: [stateColor.opacity(0.15), Color(.systemBackground)],
            startPoint: .top, endPoint: .center
        )
    }

    // MARK: - Glucose Card

    private var glucoseCard: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(.ultraThinMaterial)
                .shadow(color: stateColor.opacity(0.3), radius: 12, y: 4)
            if let g = manager.glucoseReading {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(g.glucoseMgDl)")
                        .font(.system(size: 80, weight: .black, design: .rounded))
                        .foregroundStyle(glucoseColor(g.glucoseMgDl))
                    VStack(alignment: .leading, spacing: 4) {
                        Text(g.trendArrow).font(.system(size: 36))
                        Text("mg/dL").font(.headline).foregroundStyle(.secondary)
                        Text(String(format: "%+.1f", g.rateOfChange))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(24)
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "drop.fill")
                        .font(.system(size: 40)).foregroundStyle(stateColor.opacity(0.5))
                    Text("No reading yet").font(.headline).foregroundStyle(.secondary)
                    Text(manager.state.rawValue).font(.caption).foregroundStyle(.tertiary)
                }
                .padding(32)
            }
        }
    }

    // MARK: - Status Card

    private var statusCard: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(stateColor.opacity(0.2)).frame(width: 44, height: 44)
                Circle().fill(stateColor).frame(width: 14, height: 14).shadow(color: stateColor, radius: 4)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(manager.state.rawValue).font(.headline)
                Text(manager.crypto.nonceBackVariant.rawValue)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            connectButton
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private var connectButton: some View {
        let isIdle = manager.state == .idle || manager.state == .failed
        return Button(action: {
            if isIdle { manager.startScan() } else { manager.stopScan() }
        }) {
            Label(
                isIdle ? "Connect" : "Disconnect",
                systemImage: isIdle ? "antenna.radiowaves.left.and.right" : "xmark.circle.fill"
            )
            .font(.subheadline.weight(.semibold))
            .padding(.horizontal, 14).padding(.vertical, 8)
            .background(isIdle ? stateColor : Color.red, in: Capsule())
            .foregroundStyle(.white)
        }
    }

    // MARK: - KDF Results Card

    private var kdfCard: some View {
        let hits   = manager.kdfResults.filter { $0.r2Matches && $0.r1Matches }
        let tagOKs = manager.kdfResults.filter { $0.tagOK && !($0.r2Matches && $0.r1Matches) }
        return VStack(alignment: .leading, spacing: 10) {
            Label("Challenge67 — \(manager.kdfResults.count) combinations", systemImage: "key.fill")
                .font(.headline).foregroundStyle(.secondary)
            if hits.isEmpty && tagOKs.isEmpty {
                Text("All \(manager.kdfResults.count) combinations: CCM tag failed")
                    .font(.caption).foregroundStyle(.red)
            }
            ForEach(tagOKs, id: \.label) { kdfRow($0) }
            ForEach(hits,   id: \.label) { kdfRow($0) }
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    @ViewBuilder
    private func kdfRow(_ r: Libre3Crypto.ChallengeResult) -> some View {
        HStack(spacing: 10) {
            Image(systemName: r.r2Matches && r.r1Matches ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(r.r2Matches && r.r1Matches ? .green : .orange)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(r.label).font(.caption.bold())
                if r.r2Matches && r.r1Matches {
                    Text("CORRECT — handshake successful!")
                        .font(.caption).foregroundStyle(.green)
                } else {
                    Text("Tag OK, r1/r2 mismatch — raw:\(r.rawDecrypted.prefix(8).map{String(format:"%02X",$0)}.joined())")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
        }
        .padding(10)
        .background(Color(.tertiarySystemBackground), in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Log Card

    private var logCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("Log", systemImage: "terminal.fill").font(.headline).foregroundStyle(.secondary)
                Spacer()
                Button(action: { withAnimation { showLog.toggle() } }) {
                    Image(systemName: showLog ? "chevron.up" : "chevron.down").foregroundStyle(.secondary)
                }
                Button(action: { manager.log.removeAll() }) {
                    Image(systemName: "trash").foregroundStyle(.secondary)
                }
            }
            .padding()

            if showLog {
                Divider()
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 1) {
                            ForEach(Array(manager.log.enumerated()), id: \.offset) { idx, line in
                                if line.hasPrefix("══") {
                                    Divider().padding(.vertical, 4).id(idx)
                                } else {
                                    Text(line)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(lineColor(line))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .textSelection(.enabled)
                                        .id(idx)
                                }
                            }
                        }
                        .padding(10)
                    }
                    .frame(maxHeight: 320)
                    .onChange(of: manager.log.count) { _, count in
                        if count > 0 { withAnimation { proxy.scrollTo(count - 1, anchor: .bottom) } }
                    }
                }
            }
        }
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    // MARK: - Helpers

    private var stateColor: Color {
        switch manager.state {
        case .authenticated, .readingData: return .green
        case .failed:                       return .red
        case .scanning, .connecting:        return .blue
        case .handshake:                    return .orange
        default:                            return .gray
        }
    }

    private func glucoseColor(_ mgdl: Int) -> Color {
        switch mgdl {
        case ..<70:    return .red
        case 70..<180: return .green
        default:       return .orange
        }
    }

    private func lineColor(_ line: String) -> Color {
        if line.contains("MATCH") || line.contains("COMPLETE") || line.contains("Glucose") { return .green }
        if line.contains("error") || line.contains("fail") || line.contains("invalid")     { return .red }
        if line.contains("No match") || line.contains("Unexpected")                        { return .orange }
        if line.contains("→")  { return .blue }
        if line.contains("←")  { return .purple }
        if line.contains("kInit") { return .yellow }
        return .primary
    }

    private func copyLog() {
        UIPasteboard.general.string = manager.log.joined(separator: "\n")
    }
}

#Preview {
    ContentView()
}
