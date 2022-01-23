// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package sarif

import (
	"strconv"
	"strings"

	horusecEntities "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	vulnEntity "github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	horusecSeverity "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

	"github.com/ZupIT/horusec/internal/entities/sarif"
)

type Sarif struct {
	analysis *horusecEntities.Analysis
}

func NewSarif(analysis *horusecEntities.Analysis) *Sarif {
	return &Sarif{
		analysis: analysis,
	}
}

func (s *Sarif) ConvertVulnerabilityToSarif() (report sarif.Report) {

	//fmt.Sprintf("The folder selected is: [%s]. Proceed? [Y/n]", s.configs.ProjectPath), "Y")

	// All runs in the report (each run is one tool's output)
	report.Runs = []sarif.ReportRun{}

	var resultsByTool = make(map[string][]sarif.Result)

	// Organize each run by its corresponding tool name
	// Each run has only one tool providing values; since we run many tools, must have many runs
	var runsByTool = make(map[string]sarif.ReportRun)

	// Organize rules by corresponding tool name, subkeying by RuleId
	// Each tool has a unique list of rules with metadata
	var rulesByToolAndId = make(map[string]map[string]sarif.Rule)

	// Organize artifacts for each run by corresponding tool name
	// Each tool has a list of artifacts which are referred to by the results
	var artifactsByToolAndName = make(map[string]map[string]sarif.Artifact)

	for index := range s.analysis.AnalysisVulnerabilities {
		vTarget := &s.analysis.AnalysisVulnerabilities[index].Vulnerability
		toolName := vTarget.SecurityTool.ToString()

		// Test for first time seeing a given tool
		if _, exists := runsByTool[toolName]; !exists {
			rulesByToolAndId[toolName] = make(map[string]sarif.Rule)
			artifactsByToolAndName[toolName] = make(map[string]sarif.Artifact)

			// create the run and the tool
			runsByTool[toolName] = sarif.ReportRun{
				Tool: s.newTool(vTarget),
			}

			// add run to main (composite) report
			report.Runs = append(report.Runs, runsByTool[toolName])
		}

		// add result to run report
		var result = s.newResult(vTarget)
		resultsByTool[toolName] = append(resultsByTool[toolName], result)

		// add artifact to run report
		var artifact = s.newArtifact(vTarget)
		artifactsByToolAndName[toolName][artifact.Location.Uri] = artifact

		// add rule to tool
		var rule = s.newRule(vTarget)
		rulesByToolAndId[toolName][rule.Id] = rule
	}

	for idx, runReport := range report.Runs {
		var toolName = runReport.Tool.Driver.Name
		var artifactMap = artifactsByToolAndName[toolName]
		var ruleMap = rulesByToolAndId[toolName]
		var resultMap = resultsByTool[toolName]

		// Integrate artifacts and rules into the run map
		// Using this intermediate map enforces uniqueness
		for _, artifact := range artifactMap {
			report.Runs[idx].Artifacts = append(report.Runs[idx].Artifacts, artifact)
		}
		for _, rule := range ruleMap {
			report.Runs[idx].Tool.Driver.Rules = append(report.Runs[idx].Tool.Driver.Rules, rule)
		}
		for _, result := range resultMap {
			report.Runs[idx].Results = append(report.Runs[idx].Results, result)
		}
	}

	return report
}

func (s *Sarif) convertNonZeroIntStr(str string) int {
	var newInt, _ = strconv.Atoi(str)
	if newInt > 0 {
		return newInt
	}
	return 1
}

func (s *Sarif) newTool(vulnerability *vulnEntity.Vulnerability) sarif.ScanTool {
	return sarif.ScanTool{
		Driver: sarif.ScanToolDriver{
			Name:               vulnerability.SecurityTool.ToString(),
			MoreInformationUri: "https://www.google.com", // TODO
			Version:            "1.0.0",                  // TODO
		},
	}
}

func (s *Sarif) newRule(vulnerability *vulnEntity.Vulnerability) sarif.Rule {
	return sarif.Rule{
		Id: vulnerability.RuleID,
		ShortDescription: sarif.TextDisplayComponent{
			Text: vulnerability.Details,
		},
		FullDescription: sarif.TextDisplayComponent{
			Text: vulnerability.Details,
		},
		HelpUri: "https://not.implemented", // TODO
		Name:    strings.Split(vulnerability.Details, "\n")[0],
	}
}

func (s *Sarif) newArtifact(vulnerability *vulnEntity.Vulnerability) sarif.Artifact {
	return sarif.Artifact{
		Location: sarif.LocationComponent{
			Uri: vulnerability.File,
		},
	}
}

func (s *Sarif) newResult(vulnerability *vulnEntity.Vulnerability) sarif.Result {
	return sarif.Result{
		Message: sarif.TextDisplayComponent{
			Text: vulnerability.Details,
		},
		Level: sarif.ResultLevel(s.convertHorusecSeverityToSarif(vulnerability.Severity)),
		Locations: []sarif.Location{
			{
				PhysicalLocation: sarif.PhysicalLocation{
					ArtifactLocation: sarif.LocationComponent{
						Uri: vulnerability.File,
					},
					Region: sarif.SnippetRegion{
						Snippet: sarif.TextDisplayComponent{
							Text: vulnerability.Code,
						},
						StartLine:   s.convertNonZeroIntStr(vulnerability.Line),
						StartColumn: s.convertNonZeroIntStr(vulnerability.Column),
					},
				},
			},
		},
		RuleId: vulnerability.RuleID,
	}
}

func (s *Sarif) convertHorusecSeverityToSarif(severity horusecSeverity.Severity) string {
	return s.getSarifSeverityMap()[severity]
}

func (s *Sarif) getSarifSeverityMap() map[horusecSeverity.Severity]string {
	return map[horusecSeverity.Severity]string{
		horusecSeverity.Critical: sarif.Error,
		horusecSeverity.High:     sarif.Error,
		horusecSeverity.Medium:   sarif.Warning,
		horusecSeverity.Low:      sarif.Note,
		horusecSeverity.Unknown:  sarif.Note,
		horusecSeverity.Info:     sarif.Note,
	}
}
