for k in \
  /System/Library/Keychains/SystemRootCertificates.keychain \
  /Library/Keychains/System.keychain \
  "$HOME/Library/Keychains/login.keychain-db"
do
  security find-certificate -a -Z "$k" 2>/dev/null |
    awk -v k="$k" '
      /^SHA-1 hash:/ {
        gsub(/[[:space:]]/, "", $3)
        print $3 "\t" k
      }
    '
done |
awk -F '\t' '
{
  sha=$1
  store=$2
  if (!(sha SUBSEP store in seen)) {
    seen[sha SUBSEP store]=1
    stores[sha]=(stores[sha] ? stores[sha] " | " : "") store
    count[sha]++
  }
}
END {
  found=0
  for (sha in count) {
    if (count[sha] > 1) {
      print sha "\t" stores[sha]
      found=1
    }
  }
  if (!found)
    print "No certificates found in multiple keychains."
}'