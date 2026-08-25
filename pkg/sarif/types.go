package sarif

type Report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool      Tool      `json:"tool"`
	Results   []Result  `json:"results"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                   string               `json:"id"`
	ShortDescription     MultiformatMessage   `json:"shortDescription"`
	FullDescription      *MultiformatMessage  `json:"fullDescription,omitempty"`
	DefaultConfiguration *RuleConfiguration  `json:"defaultConfiguration,omitempty"`
	HelpURI              string               `json:"helpUri,omitempty"`
}

type RuleConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note"
}

type Result struct {
	RuleID    string             `json:"ruleId"`
	Level     string             `json:"level"` // "error", "warning", "note"
	Message   MultiformatMessage `json:"message"`
	Locations []Location         `json:"locations"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type Artifact struct {
	Location ArtifactLocation `json:"location"`
}

type MultiformatMessage struct {
	Text string `json:"text"`
}