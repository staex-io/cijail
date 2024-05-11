#!/bin/sh
set -ex
if test "$GITHUB_ACTIONS" = "true" && test "$GITHUB_REF_TYPE" != "tag"; then
    exit 0
fi
curl \
    --silent \
    --fail \
    --location \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GITHUB_API_URL"/repos/"$GITHUB_REPOSITORY"/releases \
    -o /tmp/response \
    -d '
{
    "tag_name":"'"$GITHUB_REF_NAME"'",
    "target_commitish":"'"$GITHUB_SHA"'",
    "name":"'"$GITHUB_REF_NAME"'",
    "body":"'"Release $GITHUB_REF_NAME"'",
    "draft":false,
    "prerelease":false,
    "generate_release_notes":true
}'
cat /tmp/response
release_id="$(jq -r .id /tmp/response)"
for file in packages/*.tar.gz*; do
    name="$(basename "$file")"
    echo curl \
        --silent \
        --fail \
        --location \
        -X POST \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Content-Type: application/octet-stream" \
        "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$name" \
        --data-binary "@$file"
done
