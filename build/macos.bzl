"""macOS development bundles, provisioning and native Swift test resources."""

load("@rules_apple//apple:providers.bzl", "AppleBundleInfo")

def _quartermaster_app_impl(ctx):
    frontend = ctx.attr.frontend
    archive = frontend[AppleBundleInfo].archive
    app = ctx.actions.declare_directory("Quartermaster.app")
    ctx.actions.run_shell(
        inputs = [archive, ctx.executable.backend, ctx.file.backend_info],
        outputs = [app],
        arguments = [
            archive.path,
            ctx.executable.backend.path,
            ctx.file.backend_info.path,
            app.path,
        ],
        command = """
set -eu
staging="$4.staging"
mkdir -p "$staging"
trap 'rm -rf "$staging"' EXIT
if [ -d "$1" ]; then
    /usr/bin/ditto "$1" "$staging/Quartermaster.app"
else
    /usr/bin/unzip -q "$1" -d "$staging"
fi
/usr/bin/ditto "$staging/Quartermaster.app" "$4"
chmod -R u+w "$4"
backend="$4/Contents/Helpers/QuartermasterBackend.app"
mkdir -p "$backend/Contents/MacOS"
/usr/bin/install -m 755 "$2" "$backend/Contents/MacOS/quartermasterd"
/usr/bin/install -m 644 "$3" "$backend/Contents/Info.plist"
/usr/bin/codesign --remove-signature "$4"
rm -rf "$4/Contents/_CodeSignature"
""",
        mnemonic = "QuartermasterBundle",
        execution_requirements = {"requires-darwin": "1"},
    )
    frontend_groups = frontend[OutputGroupInfo]
    backend_groups = ctx.attr.backend[OutputGroupInfo] if OutputGroupInfo in ctx.attr.backend else struct()
    backend_dsyms = getattr(backend_groups, "dsym_folder", depset())
    return [
        DefaultInfo(
            files = depset(
                [app] + [f for f in frontend[DefaultInfo].files.to_list() if f != archive],
                transitive = [backend_dsyms],
            ),
            runfiles = ctx.runfiles(files = [app]),
        ),
        OutputGroupInfo(
            bundle = depset([app]),
            dsyms = depset(transitive = [
                getattr(frontend_groups, "dsyms", depset()),
                backend_dsyms,
            ]),
            linkmaps = getattr(frontend_groups, "linkmaps", depset()),
        ),
    ]

quartermaster_app = rule(
    implementation = _quartermaster_app_impl,
    attrs = {
        "frontend": attr.label(providers = [AppleBundleInfo], mandatory = True),
        "backend": attr.label(executable = True, cfg = "target", mandatory = True),
        "backend_info": attr.label(allow_single_file = [".plist"], mandatory = True),
    },
)

def _provisioning_id(number):
    return "0000000000000000000000" + str(number)

def _provisioning_target(objects, number, name):
    target, product, configuration, configurations, sources, source = [_provisioning_id(number + offset) for offset in range(6)]
    objects[target] = {
        "isa": "PBXNativeTarget",
        "name": name,
        "productName": name,
        "productType": "com.apple.product-type.application",
        "productReference": product,
        "buildConfigurationList": configurations,
        "buildPhases": [sources],
        "buildRules": [],
        "dependencies": [],
    }
    objects[product] = {"isa": "PBXFileReference", "explicitFileType": "wrapper.application", "path": name + ".app", "sourceTree": "BUILT_PRODUCTS_DIR"}
    objects[configuration] = {
        "isa": "XCBuildConfiguration",
        "name": "Debug",
        "buildSettings": {
            "CODE_SIGN_ENTITLEMENTS": name + ".entitlements",
            "CODE_SIGN_INJECT_BASE_ENTITLEMENTS": "NO",
            "CODE_SIGN_STYLE": "Automatic",
            "ENABLE_HARDENED_RUNTIME": "YES",
            "INFOPLIST_FILE": name + "-Info.plist",
            "PRODUCT_NAME": name,
        },
    }
    objects[configurations] = {"isa": "XCConfigurationList", "buildConfigurations": [configuration], "defaultConfigurationName": "Debug"}
    objects[sources] = {"isa": "PBXSourcesBuildPhase", "files": [source], "buildActionMask": 2147483647, "runOnlyForDeploymentPostprocessing": 0}
    objects[source] = {"isa": "PBXBuildFile", "fileRef": _provisioning_id(15)}
    return target

def _provisioning_project_impl(ctx):
    project = _provisioning_id(10)
    group = _provisioning_id(11)
    products = _provisioning_id(12)
    configurations = _provisioning_id(13)
    configuration = _provisioning_id(14)
    source = _provisioning_id(15)
    objects = {}
    targets = [_provisioning_target(objects, 20, "Quartermaster"), _provisioning_target(objects, 30, "QuartermasterBackend")]
    objects[project] = {
        "isa": "PBXProject",
        "compatibilityVersion": "Xcode 14.0",
        "attributes": {"TargetAttributes": {target: {"ProvisioningStyle": "Automatic"} for target in targets}},
        "buildConfigurationList": configurations,
        "mainGroup": group,
        "productRefGroup": products,
        "projectDirPath": "",
        "projectRoot": "",
        "targets": targets,
    }
    objects[group] = {"isa": "PBXGroup", "children": [source, products], "sourceTree": "<group>"}
    objects[products] = {"isa": "PBXGroup", "children": [_provisioning_id(21), _provisioning_id(31)], "name": "Products", "sourceTree": "<group>"}
    objects[configurations] = {"isa": "XCConfigurationList", "buildConfigurations": [configuration], "defaultConfigurationName": "Debug"}
    objects[configuration] = {
        "isa": "XCBuildConfiguration",
        "name": "Debug",
        "buildSettings": {
            "ALWAYS_SEARCH_USER_PATHS": "NO",
            "MACOSX_DEPLOYMENT_TARGET": "26.0",
            "REGISTER_APP_WITH_LAUNCH_SERVICES": "NO",
            "SDKROOT": "macosx",
        },
    }
    objects[source] = {"isa": "PBXFileReference", "lastKnownFileType": "sourcecode.c.c", "path": "stub.c", "sourceTree": "<group>"}
    template = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(template, json.encode({"archiveVersion": "1", "objectVersion": "56", "classes": {}, "rootObject": project, "objects": objects}))
    output = ctx.actions.declare_directory(ctx.label.name)
    ctx.actions.run_shell(
        inputs = [template, ctx.file.frontend_info, ctx.file.backend_info, ctx.file.frontend_entitlements, ctx.file.backend_entitlements],
        outputs = [output],
        arguments = [output.path, template.path, ctx.file.frontend_info.path, ctx.file.backend_info.path, ctx.file.frontend_entitlements.path, ctx.file.backend_entitlements.path],
        command = """
set -eu
mkdir -p "$1/QuartermasterProvisioning.xcodeproj"
project="$1/QuartermasterProvisioning.xcodeproj/project.pbxproj"
/usr/bin/plutil -convert xml1 -o "$project" "$2"
cp "$3" "$1/Quartermaster-Info.plist"
cp "$4" "$1/QuartermasterBackend-Info.plist"
cp "$5" "$1/Quartermaster.entitlements"
cp "$6" "$1/QuartermasterBackend.entitlements"
printf 'int main(void) { return 0; }\\n' > "$1/stub.c"
for entry in '22 Quartermaster' '32 QuartermasterBackend'; do
    set -- "$1" $entry
    settings="objects.0000000000000000000000$2.buildSettings"
    identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$1/$3-Info.plist")
    executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$1/$3-Info.plist")
    /usr/bin/plutil -insert "$settings.PRODUCT_BUNDLE_IDENTIFIER" -string "$identifier" "$project"
    /usr/bin/plutil -insert "$settings.EXECUTABLE_NAME" -string "$executable" "$project"
done
""",
        mnemonic = "ProvisioningProject",
        execution_requirements = {"requires-darwin": "1"},
    )
    return [DefaultInfo(files = depset([output]), runfiles = ctx.runfiles(files = [output]))]

provisioning_project = rule(
    implementation = _provisioning_project_impl,
    attrs = {
        "frontend_info": attr.label(allow_single_file = [".plist"], mandatory = True),
        "backend_info": attr.label(allow_single_file = [".plist"], mandatory = True),
        "frontend_entitlements": attr.label(allow_single_file = [".entitlements"], mandatory = True),
        "backend_entitlements": attr.label(allow_single_file = [".entitlements"], mandatory = True),
    },
)

def _swift_test_resources_impl(ctx):
    bundle = ctx.actions.declare_directory(ctx.label.name + ".bundle")
    accessor = ctx.actions.declare_file(ctx.label.name + ".swift")
    arguments = [bundle.path]
    for source in ctx.files.srcs:
        arguments.extend([source.path, source.short_path.split("/Fixtures/")[1]])
    ctx.actions.run_shell(
        inputs = ctx.files.srcs,
        outputs = [bundle],
        arguments = arguments,
        command = """
set -eu
bundle=$1
shift
mkdir -p "$bundle/Fixtures"
cat > "$bundle/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.quartermaster.tests.resources</string>
<key>CFBundlePackageType</key><string>BNDL</string>
</dict></plist>
EOF
while [ "$#" -gt 0 ]; do
    mkdir -p "$bundle/Fixtures/$(dirname "$2")"
    cp "$1" "$bundle/Fixtures/$2"
    shift 2
done
""",
        mnemonic = "SwiftTestResources",
    )
    ctx.actions.write(
        accessor,
        """import Foundation

extension Bundle {
    static let module: Bundle = {
        let environment = ProcessInfo.processInfo.environment
        guard let root = environment["TEST_SRCDIR"], let workspace = environment["TEST_WORKSPACE"],
            let bundle = Bundle(path: root + "/" + workspace + "/" + %s)
        else { fatalError("Bazel test resource bundle is missing") }
        return bundle
    }()
}
""" % json.encode(bundle.short_path),
    )
    return [
        DefaultInfo(files = depset([bundle]), runfiles = ctx.runfiles(files = [bundle])),
        OutputGroupInfo(swift_sources = depset([accessor])),
    ]

swift_test_resources = rule(
    implementation = _swift_test_resources_impl,
    attrs = {"srcs": attr.label_list(allow_files = True)},
)
