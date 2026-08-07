from setuptools import setup

# Tools for  a custom version string, rather than the confusing one that
def custom_version_scheme(version):
    # Returns just the tag string safely
    return str(version.tag)

def custom_local_scheme(version):
    parts = []

    # Add node hash if we are ahead of the tag
    if version.distance and version.distance > 0:
        #parts.append(f"+{version.node[1:9]}-{version.distance}")
        parts.append(f"+{version.distance}")
        parts.append(f"-{version.node[1:13]}")

    # Append dirty flag if workspace has uncommitted changes
    if version.dirty:
        # Avoid double plus signs if node was already added
        prefix = "-" if parts else "+"
        parts.append(f"{prefix}dirty")

    return "".join(parts)

setup(
    use_scm_version={
        "version_scheme": custom_version_scheme,
        "local_scheme": custom_local_scheme,
    },
)
