**Unreleased**
* Convert app to the Splunk SOAR SDK (splunk-soar-sdk 3.25.3)
* Restore the classic nested action_result.data.* datapath contract on all lookup actions
* enrichmentResults.*.result is now always a JSON string; previous versions parsed json-format enrichment results into an object at runtime
* Datapath shape corrections on lookup actions: exploitStage and path are objects (.name/.classification), originatingIps is a list of objects, and hitCount is numeric, matching actual API payloads
