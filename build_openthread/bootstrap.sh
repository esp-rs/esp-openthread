#!/bin/bash

set -euxo pipefail

if [[ -n ${BASH_SOURCE[0]} ]]; then
    script_path="${BASH_SOURCE[0]}"
else
    script_path="$0"
fi
script_dir="$(realpath "$(dirname "${script_path}")")"
repo_dir="$(dirname "${script_dir}")"

do_bootstrap_openthread()
{
    echo "Bootstrapping openthread"
    "${repo_dir}"/build_openthread/openthread/script/bootstrap
}

do_bootstrap_openthread
