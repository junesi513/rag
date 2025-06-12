import json

def update_data():
    # load data file
    data_items = []
    repos_items = {}
    mismatches = []
    
    # read data.jsonl file
    with open("knowledge/data.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            data_items.append(json.loads(line))
    
    # read ReposVul_java_extracted.jsonl file
    with open("knowledge/ReposVul_java_extracted.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            repos_items[item["cve_id"]] = item
    
    # add code_before and record mismatches
    for item in data_items:
        # find CVE ID
        cve_id = next((key for key in item.keys() if key.startswith("CVE-")), None)
        if cve_id and cve_id in repos_items:
            # get code_before from each detail and add to file_specific_analysis
            code_by_filename = {detail["file_name"]: detail["code_before"] for detail in repos_items[cve_id]["details"]}
            
            for analysis in item[cve_id]["file_specific_analysis"]:
                if analysis["filename"] in code_by_filename:
                    analysis["code"] = code_by_filename[analysis["filename"]]
                else:
                    analysis["code"] = ""
        else:
            mismatches.append(item)
    
    # save updated data.jsonl
    with open("knowledge/data.jsonl", "w", encoding="utf-8") as f:
        for item in data_items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    
    # save mismatches
    with open("knowledge/mismatch.json", "w", encoding="utf-8") as f:
        json.dump(mismatches, f, ensure_ascii=False, indent=2)
    
    print(f"processing completed:")
    print(f"- matched items: {len(data_items) - len(mismatches)}")
    print(f"- mismatched items: {len(mismatches)}")

if __name__ == "__main__":
    update_data() 