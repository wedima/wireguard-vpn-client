import { execSync } from 'child_process'
import { readFileSync, writeFileSync } from 'fs'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = resolve(__dirname, '..')

const bump = process.argv[2]
if (!['patch', 'minor', 'major'].includes(bump)) {
  console.error('Usage: node scripts/release.mjs <patch|minor|major>')
  process.exit(1)
}

const pkgPath = resolve(root, 'package.json')
const tauriConfPath = resolve(root, 'src-tauri/tauri.conf.json')
const cargoPath = resolve(root, 'src-tauri/Cargo.toml')

const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
const [major, minor, patch] = pkg.version.split('.').map(Number)

let newVersion
if (bump === 'major') newVersion = `${major + 1}.0.0`
else if (bump === 'minor') newVersion = `${major}.${minor + 1}.0`
else newVersion = `${major}.${minor}.${patch + 1}`

const tag = `v${newVersion}`
console.log(`Bumping ${pkg.version} → ${newVersion} (tag: ${tag})`)

pkg.version = newVersion
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n')

const tauriConf = JSON.parse(readFileSync(tauriConfPath, 'utf8'))
tauriConf.version = newVersion
writeFileSync(tauriConfPath, JSON.stringify(tauriConf, null, 2) + '\n')

const cargo = readFileSync(cargoPath, 'utf8')
writeFileSync(cargoPath, cargo.replace(/^version = ".*?"/m, `version = "${newVersion}"`))

execSync('git add package.json src-tauri/tauri.conf.json src-tauri/Cargo.toml', { stdio: 'inherit' })
execSync(`git commit -m "chore: release ${tag}"`, { stdio: 'inherit' })
execSync(`git tag ${tag}`, { stdio: 'inherit' })
execSync('git push && git push --tags', { stdio: 'inherit' })

console.log(`\n✓ ${tag} gepusht — GitHub Actions baut jetzt alle Plattformen`)
console.log(`  Windows nachliefern: GitHub → Actions → "Release Windows (Nachliefern)" → Run workflow → Tag: ${tag}`)
