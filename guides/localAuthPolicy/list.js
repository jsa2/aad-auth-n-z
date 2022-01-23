main()
async function main () {
    var d = require('./def.json').filter(item => item.displayName == "Local_Authentication_auditing")
    var arr = []
    d[0].policyDefinitions.map(item => arr.push({policyDefinitionId:item.policyDefinitionId}))
    
    require('fs').writeFileSync('localAuthd.json',JSON.stringify(arr))
}