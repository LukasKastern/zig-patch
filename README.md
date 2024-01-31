# What is zig-patch?

zig-patch is a highly concurrent command line tool for incrementally updating software.

Its core algorithms are based on the [wharf spec](https://itch.io/docs/wharf/).  

## Prequisites
[Zig (0.11)](https://ziglang.org/download/).

## Build the project

```
git clone https://github.com/LukasKastern/zig-patch.git
cd zig-patch
zig build -Doptimize=ReleaseFast
```

## Usage

Zig-patch can be used with or without a reference.

A reference to a previous version is called a **signature file**. 

**Signature files** contain the file structure as well as the hashed content of the version.

### Full Patch
A full patch refers to a patch that is not based on a previous version.

```
zig-patch create --source_folder "/MyBuild" 
```

Once complete this will have generated a **Patch.pwd** and **Patch.signature** in the working directorry.

### Incremental Patch

The more interesting usage is to base a version on a previous one.

In this case only blocks that haven't existed in the reference will be written to the patch.

```
zig-patch create --source_folder "/MyBuildV2" --signature_file "SignatureOfMyPreviousBuild.signature"
```

### Applying A Patch

Without a reference:
```
zig-patch apply --patch "/PatchFile.pwd" --target_folder "/MyBuild"
```

With a reference:
```
zig-patch apply --patch "/PatchFile.pwd" --reference_folder "MyBuild" --target_folder "/MyBuildV2FromPatch"
````

### Extra

Some commands allow additional arguments. Like the worker count to use or compression level. 

Run ***zig-patch command --help*** for more info.

#### Linux Notes

Generating patches for large folders might fail.

If so increase the limit of open file handles to suit the amount of files in the folders you are going to patch.

For example:

````
ulimit -n 8096
````
