#!/bin/bash

LATEST_VERSION=$(curl -s 'https://api.github.com/repos/opentdf/client-cpp/releases/latest' | jq -r '.tag_name')
WORKFLOW_FILE=".github/workflows/build.yml"
CONAN_FILE="conanfile.py"

PAT="$ACCESS_TOKEN"

git config --global user.name "${GITHUB_ACTOR}"
git config --global user.email "${GITHUB_ACTOR}@users.noreply.github.com"
branch_name="automatic-update-to-$LATEST_VERSION"

cd wrapper_repo

git checkout -b $branch_name

# Update conanfile.py
conanfile_path=$CONAN_FILE
config_conan=$(cat $conanfile_path)
search_line='self.requires("opentdf-client/'
new_conanfile_content=$(echo "$config_conan" | sed "s|${search_line}[0-9.]*@|${search_line}${LATEST_VERSION}@|")
echo "$new_conanfile_content" > "$conanfile_path"
git add "$conanfile_path"

# Update build.yml
build_yml_path=$WORKFLOW_FILE
config_yaml=$(cat $build_yml_path)
new_build_yml_content=$(echo "$config_yaml" | sed "s/VCLIENT_CPP_VER: .*/VCLIENT_CPP_VER: $LATEST_VERSION/")
echo "$new_build_yml_content" > "$build_yml_path"
git add "$build_yml_path"

# Commit changes
git commit -m "Automatic update to client-cpp $LATEST_VERSION"

git push --set-upstream origin "$branch_name" -f

gh pr create \
    --body "Automated PR created by GitHub Actions" \
    --title "Update to client-cpp $LATEST_VERSION" \
    --head "$branch_name" \
    --base "main"

