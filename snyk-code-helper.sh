#Snyk Code Helper
#!/bin/bash
RED='\033[1;31m'
ORANGE='\033[1;33m'
CYAN='\033[1;36m'
GRAY='\033[1;30m'
GREEN='\033[1;32m'
PURPLE='\033[1;35m'
BLUE='\033[1;34m'
NC='\033[0m' 

printf "\n"
echo "${PURPLE}Snyk Code Helper${NC}"

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
    echo "${PURPLE}>>>>>>>> $ISSUE <<<<<<<<${NC}"
    
    printf  "File: " 
    FILENAME=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].locations[].physicalLocation.artifactLocation.uri')
    echo $FILENAME

    printf "Snyk Priority Score: "
    PRIORITY=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].properties.priorityScore')
    echo ${PURPLE}$PRIORITY${NC}

    printf "Severity: "
    SEVERITY=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].level')
            if [[ "$SEVERITY" == '"error"' ]]; then 
                echo "${RED}High${NC}"
            elif [[ "$SEVERITY" == '"warning"' ]]; then 
                echo "${CYAN}Medium${NC}"
            elif [[ "$SEVERITY" == '"note"' ]]; then 
                echo "${GRAY}Low${NC}"
            fi
    
    printf "Affected Line(s): "
    STARTLINE=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].locations[].physicalLocation.region.startLine')
    ENDLINE=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].locations[].physicalLocation.region.endLine')
    echo "The issue is located from line $STARTLINE to line $ENDLINE in $FILENAME"

    printf "Remediation Guidance: "
    MESSAGE=$(cat snyk_code_results.json | jq '.runs[0].results['$i'].message.text')
    echo ${GREEN}$MESSAGE${NC}
 
    printf "\n"
    printf "${BLUE}Fix Inspiration${NC} \n"
    for j in $(seq 0 2); do
        printf "Source: "
        EXAMPLEGITURL=$(cat snyk_code_results.json | jq '.runs[0].tool.driver.rules[] | select(.id=='$RULEID')| .properties.exampleCommitFixes['$j'].commitURL')
        echo $EXAMPLEGITURL
        printf "\n"

        NUMOFLINES=$(cat snyk_code_results.json | jq '.runs[0].tool.driver.rules[] | select(.id=='$RULEID')| .properties.exampleCommitFixes['$j'].lines | length')
        NUMOFLINES=$((NUMOFLINES - 1)); 
        for k in $(seq 0 $NUMOFLINES); do
            CODELINE=$(cat snyk_code_results.json | jq '.runs[0].tool.driver.rules[] | select(.id=='$RULEID')| .properties.exampleCommitFixes['$j'].lines['$k'].line')
            CODELINENUMBER=$(cat snyk_code_results.json | jq '.runs[0].tool.driver.rules[] | select(.id=='$RULEID')| .properties.exampleCommitFixes['$j'].lines['$k'].lineNumber')
            CODELINECHANGE=$(cat snyk_code_results.json | jq '.runs[0].tool.driver.rules[] | select(.id=='$RULEID')| .properties.exampleCommitFixes['$j'].lines['$k'].lineChange')
            if [[ "$CODELINECHANGE" == '"removed"' ]]; then 
                echo "${RED}$CODELINENUMBER:  $CODELINE${NC}"
            elif [[ "$CODELINECHANGE" == '"added"' ]]; then 
                echo "${GREEN}$CODELINENUMBER:  $CODELINE${NC}"
            elif [[ "$CODELINECHANGE" == '"none"' ]]; then 
                echo "$CODELINENUMBER:  $CODELINE"
            fi
        done
        printf "\n"
    done
    printf "\n\n"
done


rm snyk_code_results.json