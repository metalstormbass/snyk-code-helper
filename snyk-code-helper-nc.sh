#Snyk Code Helper
#!/bin/bash

printf "\n"
echo "Snyk Code Helper"

if [ -e snyk_code_results.json ]
then
    rm snyk_code_results.json
fi


if [ -p /dev/stdin ]; then
        echo "Processing Snyk Code Data!"
        printf "\n"
        while IFS= read -r line; do
              printf '%s ' ${line} >> snyk_code_results.json

        done
else
        echo "This script requires input from Snyk Code"
        echo "Example command: ${BLUE}snyk code test --json | ./snyk-code-helper.sh${NC}"
        printf "\n"
        exit
fi

RESULT=$(cat snyk_code_results.json | jq '.runs[0].results' | jq length ); 
RESULT=$((RESULT - 1)); 

for i in $(seq 0 $RESULT); do

    RULEID=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].ruleId')         
    ISSUE=$(cat snyk_code_results.json | jq '.runs[0].tool.driver.rules[] | select(.id=='$RULEID')| .shortDescription.text')  
    echo ">>>>>>>> $ISSUE <<<<<<<<"
    
    printf  "File: " 
    FILENAME=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].locations[].physicalLocation.artifactLocation.uri')
    echo $FILENAME

    printf "Snyk Priority Score: "
    PRIORITY=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].properties.priorityScore')
    echo $PRIORITY

    printf "Severity: "
    SEVERITY=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].level')
            if [[ "$SEVERITY" == '"error"' ]]; then 
                echo "High"
            elif [[ "$SEVERITY" == '"warning"' ]]; then 
                echo "Medium"
            elif [[ "$SEVERITY" == '"note"' ]]; then 
                echo "Low"
            fi

    printf "Sink: "
    STARTLINE=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].locations[].physicalLocation.region.startLine')
    ENDLINE=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].locations[].physicalLocation.region.endLine')
    echo "The sink is located from line $STARTLINE to line $ENDLINE in $FILENAME"    

    #Dataflow
    printf "\n"
    echo "Dataflow: "
    DATAFLOWLINES=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].codeFlows[].threadFlows[].locations | length ') 
    DATAFLOWLINES=$((DATAFLOWLINES - 1));
    for j in $(seq 0 $DATAFLOWLINES); do
        DFSTART=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].codeFlows[].threadFlows[].locations['$j'].location.physicalLocation.region.startLine')
        DFEND=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].codeFlows[].threadFlows[].locations['$j'].location.physicalLocation.region.endLine')
        FILENAME=$(echo "$FILENAME" | sed -e 's/^"//' -e 's/"$//')
        
        if [[ "$DFSTART" != "$DFEXISTS" ]]; then 
            printf "$DFSTART: "
            sed -n ${DFSTART},${DFEND}p ${FILENAME}
        fi

        DFEXISTS=${DFSTART}
    done
    printf "\n"

    printf "Description: "
    MESSAGE=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].message.text')
    echo $MESSAGE

    printf "\n\n"
done


rm snyk_code_results.json