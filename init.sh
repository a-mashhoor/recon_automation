#!/usr/bin/env bash
#
# refactored this shit with ai!
# not tested on anything, use it carefully!
#
set -euo pipefail

if [[ -n "$SUDO_USER" ]]; then
	USER_HOME=$(eval echo ~"$SUDO_USER")
else
	USER_HOME=$HOME
fi

TOOLS_DIR="${USER_HOME}/.local/bin"
ZSHRC="${USER_HOME}/.zshrc"

REQUIRED_PACKAGES=(
	golang git figlet pcregrep curl wafw00f jq sed assetfinder
	subfinder dnsmap ffuf httprobe waybackpy amass dnsutils
	bind9-host nmap whois gobuster zip unzip seclists
)

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

main() {
	check_root
	check_kali
	check_zsh
	setup_path

	info "Starting system setup..."
	install_packages

	check_github_ssl

	install_github_tool "projectdiscovery/urlfinder" "urlfinder" "linux_amd64.zip"
	install_github_tool "projectdiscovery/katana" "katana" "linux_amd64.zip"

	install_go_tool "tomnomnom/hacks" "inscope"
	install_go_tool "tomnomnom/hacks" "fff"

	install_main_script

	info "Installation complete! Don't forget to:"
	echo -e "1. Run ${GREEN}source ${ZSHRC}${NC} or restart your shell"
	echo -e "2. Verify tools are in path: ${GREEN}ls ${TOOLS_DIR}${NC}"
}

cleanup() {
	echo "Cleaning up..."
	rm -rf "${temp_dir}" || true
	exit 0
}
#trap cleanup EXIT INT TERM
error() {
	echo -e "${RED}[ERROR]${NC} $1" >&2
	exit 1
}

info() {
	echo -e "${GREEN}[INFO]${NC} $1"
}

check_root() {
	if [[ $EUID -ne 0 ]]; then
		error "be root you fool"
	fi
}

check_kali() {
	local os_info
	os_info=$(hostnamectl | awk -F': ' '/Operating System:/ {print $2}')
	if [[ "$os_info" != "Kali GNU/Linux Rolling" ]]; then
		error "This script is designed for Kali Linux only"
	fi
}

check_github_ssl() {
	if ! curl -sI https://github.com | grep -q "200 OK"; then
		error "Could not verify GitHub's SSL certificate"
	fi
}
setup_ownership() {
	chown -R "${SUDO_USER}:${SUDO_USER}" "${TOOLS_DIR}"
	chown "${SUDO_USER}:${SUDO_USER}" "${ZSHRC}"
}

check_zsh() {
	if ! command -v zsh &>/dev/null; then
		error "Zsh is required but not installed"
	fi

	if [[ ${SHELL##*/} != "zsh" ]]; then
		chsh -s "$(command -v zsh)" "${SUDO_USER:-$USER}"
		info "Default shell changed to zsh. Please restart your session."
		exit 0
	fi
}

setup_path() {
	mkdir -p "${TOOLS_DIR}"
	setup_ownership

	if ! grep -q "export PATH=\$PATH:${TOOLS_DIR}" "${ZSHRC}"; then
		echo "export PATH=\$PATH:${TOOLS_DIR}" >>"${ZSHRC}"
		info "Added ${TOOLS_DIR} to PATH in .zshrc"
	fi
}

install_packages() {
	info "Updating package lists..."
	apt-get update -qq

	info "Installing required packages..."
	apt-get install -qq -y "${REQUIRED_PACKAGES[@]}"
}

install_github_tool() {
	local repo="$1"
	local name="$2"
	local pattern="$3"

	info "Installing ${name}..."
	local download_url=$(curl -s "https://api.github.com/repos/${repo}/releases/latest" |
		jq -r ".assets[] | select(.name | test(\"${pattern}\")) | .browser_download_url")

	if [[ -z "$download_url" ]]; then
		error "Failed to find download URL for ${name}"
	fi

	local temp_dir=$(mktemp -d)
	chown -R "${SUDO_USER}:${SUDO_USER}" "${temp_dir}"

	sudo -u "${SUDO_USER}" wget -q -P "${temp_dir}" "${download_url}"
	sudo -u "${SUDO_USER}" unzip -q "${temp_dir}"/*.zip -d "${temp_dir}"
	sudo -u "${SUDO_USER}" find "${temp_dir}" -maxdepth 1 -type f -executable -exec mv -t "${TOOLS_DIR}/" {} +

	rm -rf "${temp_dir}"
	setup_ownership
}

install_go_tool() {
	local repo="$1"
	local name="$2"

	info "Installing ${name}..."
	local temp_dir=$(mktemp -d)
	chown -R "${SUDO_USER}:${SUDO_USER}" "${temp_dir}"

	sudo -u "${SUDO_USER}" git clone -q "https://github.com/${repo}.git" "${temp_dir}"
	pushd "${temp_dir}" >/dev/null
	sudo -u "${SUDO_USER}" go build -o "${name}" ./*.go
	sudo -u "${SUDO_USER}" mv "${name}" "${TOOLS_DIR}/"
	popd >/dev/null

	rm -rf "${temp_dir}"
	setup_ownership
}

install_main_script() {
	local repo="a-mashhoor/recon_automation"
	local branch="master"
	local install_dir="/opt/recon_automation"
	local script_name="recon_automation.sh"
	local symlink_name="recon_aut"

	info "Installing main recon script..."

	if [[ ! -d "$install_dir" ]]; then
		git clone -q --depth 1 -b "$branch" "https://github.com/$repo.git" "$install_dir" ||
			error "Failed to clone main script repository"
	else
		info "Updating existing installation..."
		(cd "$install_dir" && sudo -u "$SUDO_USER" git reset --hard HEAD && sudo -u "$SUDO_USER" git pull -q) ||
			error "Failed to update main script"
	fi

	chown -R "${SUDO_USER}:${SUDO_USER}" "$install_dir" ||
		error "Failed to set ownership for $install_dir"

	local main_script_path="$install_dir/$script_name"
	[[ -f "$main_script_path" ]] || error "Main script not found at $main_script_path"

	local symlink_path="$TOOLS_DIR/$symlink_name"
	ln -sf "$main_script_path" "$symlink_path" ||
		{
			rm -rf "$install_dir"
			error "Failed to create symlink"
		}

	chmod +x "$main_script_path"
	setup_ownership

	info "Verifying installation..."
	if ! sudo -u "$SUDO_USER" "$symlink_name" --help &>/dev/null; then
		error "Installed script failed basic functionality check"
	fi

	info "Main script installed and symlinked to $symlink_path"
}
trap 'cleanup' EXIT INT TERM
main
