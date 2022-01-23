main()
async function main () {
    var d = require('./def.json').filter(item => item.displayName == "Local_Authentication_auditing")
    require('fs').writeFileSync('localAuth.json',JSON.stringify(d))
}