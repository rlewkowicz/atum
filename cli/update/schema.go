package update

import (
	"bytes"
	"errors"
)

const desiredSchemaFile = "atum.schema.json"
const lockSchemaFile = "atum.lock.schema.json"

// projectImageEvidenceSchema keeps the updater-owned schema synchronized with
// the immutable filesystem evidence emitted by image admission. The narrow
// replacement deliberately fails if the schema shape changes underneath this
// projection rather than introducing a second generic schema generator.
func projectImageEvidenceSchema(tree *candidateTree) error {
	data, err := tree.CandidateData(desiredSchemaFile)
	if err != nil {
		return err
	}
	const oldProperties = `              "present": {"type": "boolean"},
              "mode": {"type": "string", "pattern": "^[0-7]{4}$"},`
	const newProperties = `              "present": {"type": "boolean"},
              "type": {"$ref": "#/$defs/nonEmpty"},
              "link": {"$ref": "#/$defs/nonEmpty"},
              "mode": {"type": "string", "pattern": "^[0-7]{4}$"},`
	if bytes.Contains(data, []byte(newProperties)) {
		return projectGenericChartSchema(tree)
	}
	if bytes.Count(data, []byte(oldProperties)) != 1 {
		return errors.New(
			"project desired schema: image filesystem evidence shape is unsupported",
		)
	}
	if err := tree.Set(
		desiredSchemaFile,
		bytes.Replace(data, []byte(oldProperties), []byte(newProperties), 1),
	); err != nil {
		return err
	}
	return projectGenericChartSchema(tree)
}

func projectGenericChartSchema(tree *candidateTree) error {
	data, err := tree.CandidateData(desiredSchemaFile)
	if err != nil {
		return err
	}
	const oldRequired = `"required": ["id", "name", "valuesPath", "fluxSource", "version", "appVersion", "license", "source", "archiveSha256"],`
	const newRequired = `"required": ["id", "name", "valuesPath", "version", "appVersion", "license", "source", "archiveSha256"],`
	const obsoleteProperty = `        "fluxSource": {"$ref": "#/$defs/nonEmpty"},
`
	if bytes.Contains(data, []byte(oldRequired)) {
		if bytes.Count(data, []byte(oldRequired)) != 1 {
			return errors.New("project desired schema: generic chart source shape is unsupported")
		}
		requiredOffset := bytes.Index(data, []byte(oldRequired))
		propertyOffset := bytes.Index(data[requiredOffset:], []byte(obsoleteProperty))
		if propertyOffset < 0 {
			return errors.New("project desired schema: generic chart source property is unsupported")
		}
		propertyOffset += requiredOffset
		data = bytes.Replace(data, []byte(oldRequired), []byte(newRequired), 1)
		// The required-list replacement is shorter by the exact removed key.
		propertyOffset -= len(oldRequired) - len(newRequired)
		data = append(
			data[:propertyOffset],
			data[propertyOffset+len(obsoleteProperty):]...,
		)
		if err := tree.Set(desiredSchemaFile, data); err != nil {
			return err
		}
	} else if !bytes.Contains(data, []byte(newRequired)) {
		return errors.New("project desired schema: generic chart source shape is unsupported")
	}
	if err := projectFirstPartyImageSchema(tree); err != nil {
		return err
	}
	return projectChartArtifactSchema(tree)
}

func projectFirstPartyImageSchema(tree *candidateTree) error {
	data, err := tree.CandidateData(desiredSchemaFile)
	if err != nil { return err }
	const oldEnum = `"discovery": {"enum": ["rendered", "configuration", "controller-generated", "kubespray"]}`
	const newEnum = `"discovery": {"enum": ["rendered", "configuration", "first-party", "controller-generated", "kubespray"]}`
	if bytes.Contains(data, []byte(newEnum)) { return nil }
	if bytes.Count(data, []byte(oldEnum)) != 1 {
		return errors.New("project desired schema: image discovery vocabulary is unsupported")
	}
	return tree.Set(desiredSchemaFile, bytes.Replace(data, []byte(oldEnum), []byte(newEnum), 1))
}

func projectChartArtifactSchema(tree *candidateTree) error {
	data, err := tree.CandidateData(lockSchemaFile)
	if err != nil {
		return err
	}
	const oldRequired = `"required": ["clusterReleases", "bigBang", "flux", "packages", "charts", "vendors", "bootstrap"],`
	const artifactRequired = `"required": ["clusterReleases", "bigBang", "flux", "packages", "charts", "artifacts", "vendors", "bootstrap"],`
	const newRequired = `"required": ["clusterReleases", "kubespray", "bigBang", "flux", "packages", "charts", "artifacts", "vendors", "bootstrap"],`
	const oldProperty = `        "vendors": {`
	const newProperty = `        "artifacts": {
          "type": "array",
          "minItems": 1,
          "items": {"$ref": "#/$defs/chartArtifact"}
        },
        "vendors": {`
	const definitions = `    "chartArtifact": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "kind", "sourceUrl", "chartPath", "name", "version", "upstreamSha256", "archiveSha256", "size", "file", "target"],
      "properties": {
        "id": {"$ref": "#/$defs/nonEmpty"},
        "kind": {"enum": ["root", "integrated", "generic", "wrapper", "bootstrap"]},
        "sourceUrl": {"$ref": "#/$defs/nonEmpty"},
        "sourceCommit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
        "chartPath": {"$ref": "#/$defs/nonEmpty"},
        "name": {"$ref": "#/$defs/nonEmpty"},
        "version": {"$ref": "#/$defs/nonEmpty"},
        "upstreamSha256": {"$ref": "#/$defs/hexSha256"},
        "archiveSha256": {"$ref": "#/$defs/hexSha256"},
        "size": {"type": "integer", "minimum": 1, "maximum": 67108864},
        "file": {"$ref": "#/$defs/nonEmpty"},
        "target": {"$ref": "#/$defs/nonEmpty"},
        "normalizations": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["path", "from", "to"],
            "properties": {
              "path": {"$ref": "#/$defs/nonEmpty"},
              "from": {"$ref": "#/$defs/nonEmpty"},
              "to": {"$ref": "#/$defs/nonEmpty"}
            }
          }
        }
      }
    },
`
	if bytes.Contains(data, []byte(newRequired)) &&
		bytes.Contains(data, []byte(`"$ref": "#/$defs/chartArtifact"`)) {
		return nil
	}
	if bytes.Contains(data, []byte(artifactRequired)) {
		if bytes.Count(data, []byte(artifactRequired)) != 1 {
			return errors.New("project lock schema: resolved artifact inventory shape is unsupported")
		}
		return tree.Set(
			lockSchemaFile,
			bytes.Replace(data, []byte(artifactRequired), []byte(newRequired), 1),
		)
	}
	if bytes.Count(data, []byte(oldRequired)) != 1 ||
		bytes.Count(data, []byte(oldProperty)) != 1 {
		return errors.New("project lock schema: chart artifact shape is unsupported")
	}
	data = bytes.Replace(data, []byte(oldRequired), []byte(newRequired), 1)
	data = bytes.Replace(data, []byte(oldProperty), []byte(newProperty), 1)
	const definitionAnchor = `    "nonEmpty": {"type": "string", "minLength": 1},`
	if bytes.Count(data, []byte(definitionAnchor)) != 1 {
		return errors.New("project lock schema: definitions anchor is unsupported")
	}
	data = bytes.Replace(
		data,
		[]byte(definitionAnchor),
		[]byte(definitionAnchor+"\n"+definitions),
		1,
	)
	return tree.Set(lockSchemaFile, data)
}
