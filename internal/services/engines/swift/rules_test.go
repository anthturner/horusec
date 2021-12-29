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

import (
	"testing"

	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestRulesVulnerableCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-SWIFT-2",
			Rule: NewCoreDataDatabase(),
			Src:  SampleVulnerableHSSWIFT2,
			Findings: []engine.Finding{
				{
					CodeSample: `var mainContext: NSManagedObjectContext {`,
					SourceLocation: engine.Location{
						Line:   13,
						Column: 21,
					},
				},
			},
		},
		{
			Name: "HS-SWIFT-3",
			Rule: NewDTLS11NotUsed(),
			Src:  SampleVulnerableHSSWIFT3,
			Findings: []engine.Finding{
				{
					CodeSample: `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.DTLSv11`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 40,
					},
				},
			},
		},
		{
			Name: "HS-SWIFT-4",
			Rule: NewTLS13NotUsed(),
			Src:  SampleVulnerableHSSWIFT4,
			Findings: []engine.Finding{
				{
					CodeSample: `var tlsMinimumSupportedProtocolVersion: tls_protocol_version_t.TLSv11`,
					SourceLocation: engine.Location{
						Line:   3,
						Column: 40,
					},
				},
			},
		},
		{
			Name: "HS-SWIFT-5",
			Rule: NewReverseEngineering(),
			Src:  SampleVulnerableHSSWIFT5,
			Findings: []engine.Finding{
				{
					CodeSample: `.library(name: "FridaGadget", targets: ["FridaGadget"]),`,
					SourceLocation: engine.Location{
						Line:   8,
						Column: 25,
					},
				},
			},
		},
		{
			Name: "HS-SWIFT-6",
			Rule: NewWeakMD5CryptoCipher(),
			Src:  SampleVulnerableHSSWIFT6,
			Findings: []engine.Finding{
				{
					CodeSample: `import CryptoSwift`,
					SourceLocation: engine.Location{
						Line:   1,
						Column: 0,
					},
				},
			},
		},
		//{
		//	Name: "HS-SWIFT-7",
		//	Rule: NewWeakCommonDesCryptoCipher(),
		//	Src:  SampleVulnerableHSSWIFT7,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-8",
		//	Rule: NewWeakIDZDesCryptoCipher(),
		//	Src:  SampleVulnerableHSSWIFT8,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-9",
		//	Rule: NewWeakBlowfishCryptoCipher(),
		//	Src:  SampleVulnerableHSSWIFT9,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-10",
		//	Rule: NewMD6Collision(),
		//	Src:  SampleVulnerableHSSWIFT10,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-11",
		//	Rule: NewMD5Collision(),
		//	Src:  SampleVulnerableHSSWIFT11,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-12",
		//	Rule: NewSha1Collision(),
		//	Src:  SampleVulnerableHSSWIFT12,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-13",
		//	Rule: NewJailbreakDetect(),
		//	Src:  SampleVulnerableHSSWIFT13,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-14",
		//	Rule: NewLoadHTMLString(),
		//	Src:  SampleVulnerableHSSWIFT14,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-15",
		//	Rule: NewWeakDesCryptoCipher(),
		//	Src:  SampleVulnerableHSSWIFT15,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-16",
		//	Rule: NewRealmDatabase(),
		//	Src:  SampleVulnerableHSSWIFT16,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-17",
		//	Rule: NewTLSMinimum(),
		//	Src:  SampleVulnerableHSSWIFT17,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-18",
		//	Rule: NewUIPasteboard(),
		//	Src:  SampleVulnerableHSSWIFT18,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-19",
		//	Rule: NewFileProtection(),
		//	Src:  SampleVulnerableHSSWIFT19,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-20",
		//	Rule: NewWebViewSafari(),
		//	Src:  SampleVulnerableHSSWIFT20,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-21",
		//	Rule: NewKeyboardCache(),
		//	Src:  SampleVulnerableHSSWIFT21,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-22",
		//	Rule: NewMD4Collision(),
		//	Src:  SampleVulnerableHSSWIFT22,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		//{
		//	Name: "HS-SWIFT-23",
		//	Rule: NewMD2Collision(),
		//	Src:  SampleVulnerableHSSWIFT23,
		//	Findings: []engine.Finding{
		//		{
		//			CodeSample: `import CryptoSwift`,
		//			SourceLocation: engine.Location{
		//				Line:   1,
		//				Column: 0,
		//			},
		//		},
		//	},
		//},
		{
			Name: "HS-SWIFT-24",
			Src:  SampleVulnerableHSSWIFT24,
			Rule: NewSQLInjection(),
			Findings: []engine.Finding{
				{
					CodeSample: `let err = SD.executeChange("SELECT * FROM User where user="+ valuesFromInput) {`,
					SourceLocation: engine.Location{
						Line:   2,
						Column: 13,
					},
				},
			},
		},
	}

	testutil.TestVulnerableCode(t, testcases)
}

func TestRulesSafeCode(t *testing.T) {
	testcases := []*testutil.RuleTestCase{
		{
			Name: "HS-SWIFT-2",
			Rule: NewCoreDataDatabase(),
			Src:  SampleSafeHSSWIFT2,
		},
		{
			Name: "HS-SWIFT-3",
			Rule: NewDTLS11NotUsed(),
			Src:  SampleSafeHSSWIFT3,
		},
		{
			Name: "HS-SWIFT-4",
			Rule: NewTLS13NotUsed(),
			Src:  SampleSafeHSSWIFT4,
		},
		{
			Name: "HS-SWIFT-5",
			Rule: NewReverseEngineering(),
			Src:  SampleSafeHSSWIFT5,
		},
		{
			Name: "HS-SWIFT-6",
			Rule: NewWeakMD5CryptoCipher(),
			Src:  SampleSafeHSSWIFT6,
		},
		{
			Name: "HS-SWIFT-7",
			Rule: NewWeakCommonDesCryptoCipher(),
			Src:  SampleSafeHSSWIFT7,
		},
		{
			Name: "HS-SWIFT-8",
			Rule: NewWeakIDZDesCryptoCipher(),
			Src:  SampleSafeHSSWIFT8,
		},
		{
			Name: "HS-SWIFT-9",
			Rule: NewWeakBlowfishCryptoCipher(),
			Src:  SampleSafeHSSWIFT9,
		},
		{
			Name: "HS-SWIFT-10",
			Rule: NewMD6Collision(),
			Src:  SampleSafeHSSWIFT10,
		},
		{
			Name: "HS-SWIFT-11",
			Rule: NewMD5Collision(),
			Src:  SampleSafeHSSWIFT11,
		},
		{
			Name: "HS-SWIFT-12",
			Rule: NewSha1Collision(),
			Src:  SampleSafeHSSWIFT12,
		},
		{
			Name: "HS-SWIFT-13",
			Rule: NewJailbreakDetect(),
			Src:  SampleSafeHSSWIFT13,
		},
		{
			Name: "HS-SWIFT-14",
			Rule: NewLoadHTMLString(),
			Src:  SampleSafeHSSWIFT14,
		},
		{
			Name: "HS-SWIFT-15",
			Rule: NewWeakDesCryptoCipher(),
			Src:  SampleSafeHSSWIFT15,
		},
		{
			Name: "HS-SWIFT-16",
			Rule: NewRealmDatabase(),
			Src:  SampleSafeHSSWIFT16,
		},
		{
			Name: "HS-SWIFT-17",
			Rule: NewTLSMinimum(),
			Src:  SampleSafeHSSWIFT17,
		},
		{
			Name: "HS-SWIFT-18",
			Rule: NewUIPasteboard(),
			Src:  SampleSafeHSSWIFT18,
		},
		{
			Name: "HS-SWIFT-19",
			Rule: NewFileProtection(),
			Src:  SampleSafeHSSWIFT19,
		},
		{
			Name: "HS-SWIFT-20",
			Rule: NewWebViewSafari(),
			Src:  SampleSafeHSSWIFT20,
		},
		{
			Name: "HS-SWIFT-21",
			Rule: NewKeyboardCache(),
			Src:  SampleSafeHSSWIFT21,
		},
		{
			Name: "HS-SWIFT-22",
			Rule: NewMD4Collision(),
			Src:  SampleSafeHSSWIFT22,
		},
		{
			Name: "HS-SWIFT-23",
			Rule: NewMD2Collision(),
			Src:  SampleSafeHSSWIFT23,
		},
		{
			Name: "HS-SWIFT-24",
			Src:  SampleSafeHSSWIFT24,
			Rule: NewSQLInjection(),
		},
	}
	testutil.TestSafeCode(t, testcases)
}
