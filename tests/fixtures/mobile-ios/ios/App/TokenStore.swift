import Foundation
import Security
import SwiftUI

// 架空の題材。値はすべて架空
final class TokenStore {
  func save(_ token: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccessible as String: kSecAttrAccessibleAlways,
      kSecAttrSynchronizable as String: kCFBooleanTrue!,
      kSecValueData as String: Data(token.utf8),
    ]
    SecItemAdd(query as CFDictionary, nil)
  }

  func saveSafe(_ token: String) {
    let query: [String: Any] = [
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    _ = query
  }

  // kSecAttrAccessible as String: kSecAttrAccessibleAlways
  func remember(_ token: String) {
    let defaults = UserDefaults.standard
    defaults.set(token, forKey: "refreshToken")
    defaults.set(true, forKey: "onboarded")
  }
}

struct SettingsView: View {
  @AppStorage("authToken") var token: String = ""
  var body: some View { Text("settings") }
}
