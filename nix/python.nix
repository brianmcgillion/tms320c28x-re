# SPDX-License-Identifier: MIT
#
# Distribution `tms320c28x-re` (what downstreams depend on), attribute `c28x`,
# module `c28x_rs`. None of the three names match.
{
  lib,
  buildPythonPackage,
  setuptools,
  pyyaml,
  c28xdec,
  src,
  version,
}:

buildPythonPackage {
  pname = "tms320c28x-re";
  inherit src version;
  pyproject = true;

  build-system = [ setuptools ];
  dependencies = [ pyyaml ];

  # Upstream's pyproject.toml is `[tool.uv] package = false` with no backend --
  # the repo is a plugin, not a distribution. Metadata is added here instead so
  # a downstream declaring `tms320c28x-re` finds real dist-info.
  #
  # c28xdec_path() falls back to a cargo target dir then PATH, neither of which
  # exists once installed; bake the store path in.
  postPatch = ''
    cat >> pyproject.toml <<'EOF'

    [build-system]
    requires = ["setuptools"]
    build-backend = "setuptools.build_meta"

    [tool.setuptools]
    py-modules = ["c28x_rs"]
    EOF

    substituteInPlace c28x_rs.py \
      --replace-fail 'os.environ.get("C28XDEC")' \
                     'os.environ.get("C28XDEC", "${lib.getExe c28xdec}")'
  '';

  pythonImportsCheck = [ "c28x_rs" ];

  meta = {
    description = "TMS320C28x decoder and COFF reader, over the c28xdec CLI";
    homepage = "https://github.com/brianmcgillion/tms320c28x-re";
    license = lib.licenses.mit;
  };
}
