//
//  AdGuardHomeService.swift
//  PiStatsCore
//
//  AdGuard Home API service implementation.
//  Authentication: Basic Auth using the token field.
//    - If token contains ":", it is treated as "username:password".
//    - Otherwise "admin:<token>" is assumed.
//  Leave token nil or empty for unauthenticated access.
//

import Foundation
import OSLog

internal final class AdGuardHomeService: PiholeService {
    public let pihole: Pihole
    private let urlSession: URLSession

    init(_ pihole: Pihole, urlSession: URLSession = .shared) {
        self.pihole = pihole
        self.urlSession = urlSession
    }

    // MARK: - PiholeService

    func fetchSummary() async throws -> PiholeSummary {
        Log.network.info("📊 [AGH] Fetching summary for \(self.pihole.name)")

        async let statsTask = fetchJSON(from: try makeURL(endpoint: .stats))
        async let filteringTask = fetchJSON(from: try makeURL(endpoint: .filteringStatus))

        let (stats, filtering) = try await (statsTask, filteringTask)

        let totalQueries = stats[JSONKeys.numDnsQueries.rawValue] as? Int ?? 0
        let blockedFiltering = stats[JSONKeys.numBlockedFiltering.rawValue] as? Int ?? 0
        let replacedSafebrowsing = stats[JSONKeys.numReplacedSafebrowsing.rawValue] as? Int ?? 0
        let replacedParental = stats[JSONKeys.numReplacedParental.rawValue] as? Int ?? 0
        let replacedSafesearch = stats[JSONKeys.numReplacedSafesearch.rawValue] as? Int ?? 0

        let totalBlocked = blockedFiltering + replacedSafebrowsing + replacedParental + replacedSafesearch
        let percentBlocked = totalQueries > 0 ? (Double(totalBlocked) / Double(totalQueries)) * 100.0 : 0.0

        // Sum rules_count from all enabled filters, plus custom user rules
        let filters = filtering[JSONKeys.filters.rawValue] as? [[String: Any]] ?? []
        let userRules = filtering[JSONKeys.userRules.rawValue] as? [String] ?? []
        let rulesCount = filters
            .filter { $0[JSONKeys.enabled.rawValue] as? Bool == true }
            .compactMap { $0[JSONKeys.rulesCount.rawValue] as? Int }
            .reduce(0, +) + userRules.count

        let summary = PiholeSummary(
            domainsBeingBlocked: rulesCount,
            queries: totalQueries,
            adsBlocked: totalBlocked,
            adsPercentageToday: percentBlocked,
            uniqueDomains: 0,
            queriesForwarded: max(0, totalQueries - totalBlocked)
        )

        Log.network.info("✅ [AGH] Summary fetched for \(self.pihole.name) - Queries: \(summary.queries), Blocked: \(summary.adsBlocked)")
        return summary
    }

    func fetchStatus() async throws -> PiholeStatus {
        Log.network.info("🔍 [AGH] Fetching status for \(self.pihole.name)")

        let json = try await fetchJSON(from: try makeURL(endpoint: .status))

        guard let protectionEnabled = json[JSONKeys.protectionEnabled.rawValue] as? Bool else {
            Log.network.error("❌ [AGH] No protection_enabled field in response for \(self.pihole.name)")
            throw PiholeServiceError.unknownStatus
        }

        let status: PiholeStatus = protectionEnabled ? .enabled : .disabled
        Log.network.info("✅ [AGH] Status: \(status.rawValue) for \(self.pihole.name)")
        return status
    }

    func fetchHistory() async throws -> [HistoryItem] {
        Log.network.info("📈 [AGH] Fetching history for \(self.pihole.name)")

        let json = try await fetchJSON(from: try makeURL(endpoint: .stats))

        guard let dnsQueries = json[JSONKeys.dnsQueries.rawValue] as? [Int],
              let blockedCounts = json[JSONKeys.blockedFiltering.rawValue] as? [Int] else {
            Log.network.error("❌ [AGH] Failed to parse history arrays for \(self.pihole.name)")
            throw PiholeServiceError.cannotParseResponse
        }

        let timeUnits = json[JSONKeys.timeUnits.rawValue] as? String ?? "hours"
        let unitSeconds: TimeInterval = timeUnits == "days" ? 86400 : 3600
        let count = min(dnsQueries.count, blockedCounts.count)
        let now = Date()
        let startTime = now.addingTimeInterval(-Double(count) * unitSeconds)

        let items: [HistoryItem] = (0..<count).map { i in
            let timestamp = startTime.addingTimeInterval(Double(i) * unitSeconds)
            return HistoryItem(
                timestamp: timestamp,
                blocked: blockedCounts[i],
                forwarded: max(0, dnsQueries[i] - blockedCounts[i])
            )
        }

        Log.network.info("✅ [AGH] History fetched for \(self.pihole.name) - \(items.count) items")
        return items
    }

    func enable() async throws -> PiholeStatus {
        try await setProtection(enabled: true)
    }

    func disable(timer: Int?) async throws -> PiholeStatus {
        // AdGuard Home does not natively support timed protection disable; timer is ignored.
        try await setProtection(enabled: false)
    }
}

// MARK: - Private Helpers

extension AdGuardHomeService {

    private enum Endpoint: String {
        case stats = "control/stats"
        case status = "control/status"
        case protection = "control/protection"
        case filteringStatus = "control/filtering/status"
    }

    private enum JSONKeys: String {
        case numDnsQueries = "num_dns_queries"
        case numBlockedFiltering = "num_blocked_filtering"
        case numReplacedSafebrowsing = "num_replaced_safebrowsing"
        case numReplacedParental = "num_replaced_parental"
        case numReplacedSafesearch = "num_replaced_safesearch"
        case protectionEnabled = "protection_enabled"
        case dnsQueries = "dns_queries"
        case blockedFiltering = "blocked_filtering"
        case timeUnits = "time_units"
        case filters
        case userRules = "user_rules"
        case rulesCount = "rules_count"
        case enabled
    }

    private func makeURL(endpoint: Endpoint) throws -> URL {
        let scheme = pihole.secure ? "https" : "http"
        guard let url = URL(string: "\(scheme)://\(pihole.address):\(pihole.port)/\(endpoint.rawValue)") else {
            throw PiholeServiceError.badURL
        }
        return url
    }

    /// Builds a request with Basic Auth headers when a token is configured.
    /// Token format: "username:password" or just "password" (defaults username to "admin").
    private func makeRequest(url: URL, method: String = "GET", body: Data? = nil) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let body = body {
            request.httpBody = body
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        }
        if let token = pihole.token, !token.isEmpty {
            let credentials = token.contains(":") ? token : "admin:\(token)"
            let encoded = Data(credentials.utf8).base64EncodedString()
            request.setValue("Basic \(encoded)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    private func fetchJSON(from url: URL) async throws -> [String: Any] {
        Log.network.info("🌐 [AGH] GET \(url.absoluteString)")
        let request = makeRequest(url: url)
        do {
            let (data, response) = try await urlSession.data(for: request)
            if let httpResponse = response as? HTTPURLResponse {
                Log.network.info("✅ [AGH] Response: \(httpResponse.statusCode)")
                if httpResponse.statusCode == 401 || httpResponse.statusCode == 403 {
                    throw PiholeServiceError.missingToken
                }
            }
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw PiholeServiceError.cannotParseResponse
            }
            return json
        } catch let error as PiholeServiceError {
            throw error
        } catch {
            Log.network.error("💥 [AGH] Network error for \(url.absoluteString): \(error.localizedDescription)")
            throw PiholeServiceError.networkError(error)
        }
    }

    private func setProtection(enabled: Bool) async throws -> PiholeStatus {
        let url = try makeURL(endpoint: .protection)
        let body: Data
        do {
            body = try JSONEncoder().encode(["enabled": enabled])
        } catch {
            throw PiholeServiceError.encodingError(error)
        }
        let request = makeRequest(url: url, method: "POST", body: body)
        do {
            let (_, response) = try await urlSession.data(for: request)
            if let httpResponse = response as? HTTPURLResponse {
                Log.network.info("✅ [AGH] Protection POST response: \(httpResponse.statusCode)")
                if httpResponse.statusCode == 401 || httpResponse.statusCode == 403 {
                    throw PiholeServiceError.missingToken
                }
                if httpResponse.statusCode == 200 {
                    return enabled ? .enabled : .disabled
                }
            }
            throw PiholeServiceError.unknownError
        } catch let error as PiholeServiceError {
            throw error
        } catch {
            Log.network.error("💥 [AGH] Protection action failed: \(error.localizedDescription)")
            throw PiholeServiceError.networkError(error)
        }
    }
}
