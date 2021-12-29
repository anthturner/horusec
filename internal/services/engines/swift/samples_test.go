// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package swift

const (
	SampleVulnerableHSSWIFT2 = `
class CoreDataManager {
    static let shared = CoreDataManager()
    private init() {}
    private lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "PillReminder")
        container.loadPersistentStores(completionHandler: { _, error in
            _ = error.map { fatalError("Unresolved error \($0)") }
        })
        return container
    }()
    
    var mainContext: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
    
    func backgroundContext() -> NSManagedObjectContext {
        return persistentContainer.newBackgroundContext()
    }
}
...
func savePill(pass: String) throws {
    let context = CoreDataManager.shared.backgroundContext()
    context.perform {
        let entity = Pill.entity()
        let pill = Pill(entity: entity, insertInto: context)
        pill.pass = pass
        pill.amount = 2
        pill.dozePerDay = 1
        pill.lastUpdate = Date()
        try context.save()
    }
}
`
	SampleVulnerableHSSWIFT3 = `
...
var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.DTLSv11
`
	SampleVulnerableHSSWIFT4 = `
...
var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.TLSv11
`
	SampleVulnerableHSSWIFT5 = `import PackageDescription
let package = Package(name: "Alamofire",
                      platforms: [.macOS(.v10_12),
                                  .iOS(.v10),
                                  .tvOS(.v10),
                                  .watchOS(.v3)],
                      products: [.library(name: "Alamofire", targets: ["Alamofire"]),
							 	 .library(name: "FridaGadget", targets: ["FridaGadget"]),
							 	 .library(name: "cynject", targets: ["cynject"]),
							 	 .library(name: "libcycript", targets: ["libcycript"])],
                      targets: [.target(name: "Alamofire",
                                        path: "Source",
                                        exclude: ["Info.plist"],
                                        linkerSettings: [.linkedFramework("CFNetwork",
                                                                          .when(platforms: [.iOS,
                                                                                            .macOS,
                                                                                            .tvOS,
                                                                                            .watchOS]))]),
                                .testTarget(name: "AlamofireTests",
                                            dependencies: ["Alamofire"],
                                            path: "Tests",
                                            exclude: ["Resources", "Info.plist"])],
                      swiftLanguageVersions: [.v5])`
	SampleVulnerableHSSWIFT6 = `import CryptoSwift

		"SwiftSummit".md5()
`
	SampleVulnerableHSSWIFT7 = ``
	SampleVulnerableHSSWIFT8 = ``
	SampleVulnerableHSSWIFT9 = ``
	SampleVulnerableHSSWIFT10 = ``
	SampleVulnerableHSSWIFT11 = ``
	SampleVulnerableHSSWIFT12 = ``
	SampleVulnerableHSSWIFT13 = ``
	SampleVulnerableHSSWIFT14 = ``
	SampleVulnerableHSSWIFT15 = ``
	SampleVulnerableHSSWIFT16 = ``
	SampleVulnerableHSSWIFT17 = ``
	SampleVulnerableHSSWIFT18 = ``
	SampleVulnerableHSSWIFT19 = ``
	SampleVulnerableHSSWIFT20 = ``
	SampleVulnerableHSSWIFT21 = ``
	SampleVulnerableHSSWIFT22 = ``
	SampleVulnerableHSSWIFT23 = ``
	SampleVulnerableHSSWIFT24 = `
let err = SD.executeChange("SELECT * FROM User where user="+ valuesFromInput) {
    //there was an error during the insert, handle it here
} else {
    //no error, the row was inserted successfully
}
`
)

const (
	SampleSafeHSSWIFT2 = `
class CoreDataManager {
    static let shared = CoreDataManager()
    private init() {}
    private lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "PillReminder")
        container.loadPersistentStores(completionHandler: { _, error in
            _ = error.map { fatalError("Unresolved error \($0)") }
        })
        return container
    }()
    
    var mainContext: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
    
    func backgroundContext() -> NSManagedObjectContext {
        return persistentContainer.newBackgroundContext()
    }
}
...
func savePill(pass: String) throws {
    let context = CoreDataManager.shared.backgroundContext()
    context.perform {
        let entity = Pill.entity()
        let pill = Pill(entity: entity, insertInto: context)
        pill.password = EncryptedDATAStack(passphraseKey:pass, modelName:"MyAppModel")
        pill.amount = 2
        pill.dozePerDay = 1
        pill.lastUpdate = Date()
        try context.save()
    }
}
`
	SampleSafeHSSWIFT3 = `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.DTLSv12`
	SampleSafeHSSWIFT4 = `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.TLSv12`
	SampleSafeHSSWIFT5 = `import PackageDescription
let package = Package(name: "Alamofire",
                      platforms: [.macOS(.v10_12),
                                  .iOS(.v10),
                                  .tvOS(.v10),
                                  .watchOS(.v3)],
                      products: [.library(name: "Alamofire", targets: ["Alamofire"])],
                      targets: [.target(name: "Alamofire",
                                        path: "Source",
                                        exclude: ["Info.plist"],
                                        linkerSettings: [.linkedFramework("CFNetwork",
                                                                          .when(platforms: [.iOS,
                                                                                            .macOS,
                                                                                            .tvOS,
                                                                                            .watchOS]))]),
                                .testTarget(name: "AlamofireTests",
                                            dependencies: ["Alamofire"],
                                            path: "Tests",
                                            exclude: ["Resources", "Info.plist"])],
                      swiftLanguageVersions: [.v5])`
	SampleSafeHSSWIFT6 = `import Foundation
import var CommonCrypto.CC_MD5_DIGEST_LENGTH
import func CommonCrypto.CC_MD5
import typealias CommonCrypto.CC_LONG

func MD5(string: String) -> Data {
        let length = Int(CC_MD5_DIGEST_LENGTH)
        let messageData = string.data(using:.utf8)!
        var digestData = Data(count: length)

        _ = digestData.withUnsafeMutableBytes { digestBytes -> UInt8 in
            messageData.withUnsafeBytes { messageBytes -> UInt8 in
                if let messageBytesBaseAddress = messageBytes.baseAddress, let digestBytesBlindMemory = digestBytes.bindMemory(to: UInt8.self).baseAddress {
                    let messageLength = CC_LONG(messageData.count)
                    CC_MD5(messageBytesBaseAddress, messageLength, digestBytesBlindMemory)
                }
                return 0
            }
        }
        return digestData
    }

//Test:
let md5Data = MD5(string:"Hello")`
	SampleSafeHSSWIFT7 = ``
	SampleSafeHSSWIFT8 = ``
	SampleSafeHSSWIFT9 = ``
	SampleSafeHSSWIFT10 = ``
	SampleSafeHSSWIFT11 = ``
	SampleSafeHSSWIFT12 = ``
	SampleSafeHSSWIFT13 = ``
	SampleSafeHSSWIFT14 = ``
	SampleSafeHSSWIFT15 = ``
	SampleSafeHSSWIFT16 = ``
	SampleSafeHSSWIFT17 = ``
	SampleSafeHSSWIFT18 = ``
	SampleSafeHSSWIFT19 = ``
	SampleSafeHSSWIFT20 = ``
	SampleSafeHSSWIFT21 = ``
	SampleSafeHSSWIFT22 = ``
	SampleSafeHSSWIFT23 = ``
	SampleSafeHSSWIFT24 = `
if let err = SD.executeChange("SELECT * FROM User where user=?", withArgs: [name, population, isWarm, foundedIn]) {
    //there was an error during the insert, handle it here
} else {
    //no error, the row was inserted successfully
}
`
)
