echo "Building..."
$null = npm run fetch -- --onlyChanged | out-null
$null = npm run webpack:compile | out-null

echo "Starting..."
npm run electron:start

