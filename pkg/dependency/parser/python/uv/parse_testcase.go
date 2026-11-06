package uv

import (
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	// docker run --name uv --rm -it ghcr.io/astral-sh/uv@sha256:cd6887754aa1f907b0e95cc166ac6382d16a64a136df14d09ddb7375dfc1887e sh
	// uv init normal && cd normal
	// cat >> pyproject.toml <<EOF
	// [tool.uv]
	// constraint-dependencies = ["charset-normalizer==2.1.1", "tomli==2.0.1"]
	// exclude-newer = "2024-12-20T00:00:00Z"
	// EOF
	// uv add requests==2.32.0
	// uv add --group dev pytest==8.3.4
	// uv add httpx==0.28.1 --extra socks
	// uv add jsonpointer==3.0.0 --optional json
	// apk add jq
	// uv pip list --format json |jq -c 'sort_by(.name) | .[] | {"ID": (.name + "@" + .version), "Name": .name, "Version": .version}' | sed 's/$/,/' | sed 's/\"\([^"]*\)\":/\1:/g'

	// add a root project
	// fill in the relationships between the packages
	uvNormal = []ftypes.Package{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{
			ID:           "httpx@0.28.1",
			Name:         "httpx",
			Version:      "0.28.1",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "httpx-0.28.1.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz",
					Digests:  lockfileDigests("sha256:75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "httpx-0.28.1-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad"),
				},
			},
		},
		{
			ID:           "jsonpointer@3.0.0",
			Name:         "jsonpointer",
			Version:      "3.0.0",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "jsonpointer-3.0.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/6a/0a/eebeb1fa92507ea94016a2a790b93c2ae41a7e18778f85471dc54475ed25/jsonpointer-3.0.0.tar.gz",
					Digests:  lockfileDigests("sha256:2b2d729f2091522d61c3b31f82e11870f60b68f43fbc705cb76bf4b832af59ef"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "jsonpointer-3.0.0-py2.py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/71/92/5e77f98553e9e75130c78900d000368476aed74276eb8ae8796f65f00918/jsonpointer-3.0.0-py2.py3-none-any.whl",
					Digests:  lockfileDigests("sha256:13e088adc14fca8b6aa8177c044e12701e6ad4b28ff10e65f2267a90109c9942"),
				},
			},
		},
		{
			ID:           "pytest@8.3.4",
			Name:         "pytest",
			Version:      "8.3.4",
			Relationship: ftypes.RelationshipDirect,
			Dev:          true,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "pytest-8.3.4.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/05/35/30e0d83068951d90a01852cb1cef56e5d8a09d20c7f511634cc2f7e0372a/pytest-8.3.4.tar.gz",
					Digests:  lockfileDigests("sha256:965370d062bce11e73868e0335abac31b4d3de0e82f4007408d242b4f8610761"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "pytest-8.3.4-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/11/92/76a1c94d3afee238333bc0a42b82935dd8f9cf8ce9e336ff87ee14d9e1cf/pytest-8.3.4-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:50e16d954148559c9a74109af1eaf0c945ba2d8f30f0a3d3335edde19788b6f6"),
				},
			},
		},
		{
			ID:           "requests@2.32.0",
			Name:         "requests",
			Version:      "2.32.0",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "requests-2.32.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/28/a2/423f4d16d6934ef502f10ad56673719dd4345e656aedbd6687ccc359ffc5/requests-2.32.0.tar.gz",
					Digests:  lockfileDigests("sha256:fa5490319474c82ef1d2c9bc459d3652e3ae4ef4c4ebdd18a21145a47ca4b6b8"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "requests-2.32.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/24/e8/09e8d662a9675a4e4f5dd7a8e6127b463a091d2703ed931a64aa66d00065/requests-2.32.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:f2c3881dddb70d056c5bd7600a4fae312b2a300e39be6a118d30b90bd27262b5"),
				},
			},
		},
		{
			ID:           "anyio@4.7.0",
			Name:         "anyio",
			Version:      "4.7.0",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "anyio-4.7.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/f6/40/318e58f669b1a9e00f5c4453910682e2d9dd594334539c7b7817dabb765f/anyio-4.7.0.tar.gz",
					Digests:  lockfileDigests("sha256:2f834749c602966b7d456a7567cafcb309f96482b5081d14ac93ccd457f9dd48"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "anyio-4.7.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/a0/7a/4daaf3b6c08ad7ceffea4634ec206faeff697526421c20f07628c7372156/anyio-4.7.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:ea60c3723ab42ba6fff7e8ccb0488c898ec538ff4df1f1d5e642c3601d07e352"),
				},
			},
		},
		{
			ID:           "certifi@2024.12.14",
			Name:         "certifi",
			Version:      "2024.12.14",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "certifi-2024.12.14.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/0f/bd/1d41ee578ce09523c81a15426705dd20969f5abf006d1afe8aeff0dd776a/certifi-2024.12.14.tar.gz",
					Digests:  lockfileDigests("sha256:b650d30f370c2b724812bee08008be0c4163b163ddaec3f2546c1caf65f191db"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "certifi-2024.12.14-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/a5/32/8f6669fc4798494966bf446c8c4a162e0b5d893dff088afddf76414f70e1/certifi-2024.12.14-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:1275f7a45be9464efc1173084eaa30f866fe2e47d389406136d332ed4967ec56"),
				},
			},
		},
		{
			ID:           "charset-normalizer@2.1.1",
			Name:         "charset-normalizer",
			Version:      "2.1.1",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "charset-normalizer-2.1.1.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/a1/34/44964211e5410b051e4b8d2869c470ae8a68ae274953b1c7de6d98bbcf94/charset-normalizer-2.1.1.tar.gz",
					Digests:  lockfileDigests("sha256:5a3d016c7c547f69d6f81fb0db9449ce888b418b5b9952cc5e6e66843e9dd845"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "charset_normalizer-2.1.1-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/db/51/a507c856293ab05cdc1db77ff4bc1268ddd39f29e7dc4919aa497f0adbec/charset_normalizer-2.1.1-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:83e9a75d1911279afd89352c68b45348559d1fc0506b054b346651b5e7fee29f"),
				},
			},
		},
		{
			ID:           "colorama@0.4.6",
			Name:         "colorama",
			Version:      "0.4.6",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "colorama-0.4.6.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/d8/53/6f443c9a4a8358a93a6792e2acffb9d9d5cb0a5cfd8802644b7b1c9a02e4/colorama-0.4.6.tar.gz",
					Digests:  lockfileDigests("sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "colorama-0.4.6-py2.py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/d1/d6/3965ed04c63042e047cb6a3e6ed1a63a35087b6a609aa3a15ed8ac56c221/colorama-0.4.6-py2.py3-none-any.whl",
					Digests:  lockfileDigests("sha256:4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6"),
				},
			},
		},
		{
			ID:           "exceptiongroup@1.2.2",
			Name:         "exceptiongroup",
			Version:      "1.2.2",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "exceptiongroup-1.2.2.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/09/35/2495c4ac46b980e4ca1f6ad6db102322ef3ad2410b79fdde159a4b0f3b92/exceptiongroup-1.2.2.tar.gz",
					Digests:  lockfileDigests("sha256:47c2edf7c6738fafb49fd34290706d1a1a2f4d1c6df275526b62cbb4aa5393cc"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "exceptiongroup-1.2.2-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/02/cc/b7e31358aac6ed1ef2bb790a9746ac2c69bcb3c8588b41616914eb106eaf/exceptiongroup-1.2.2-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:3111b9d131c238bec2f8f516e123e14ba243563fb135d3fe885990585aa7795b"),
				},
			},
		},
		{
			ID:           "h11@0.14.0",
			Name:         "h11",
			Version:      "0.14.0",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "h11-0.14.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/f5/38/3af3d3633a34a3316095b39c8e8fb4853a28a536e55d347bd8d8e9a14b03/h11-0.14.0.tar.gz",
					Digests:  lockfileDigests("sha256:8f19fbbe99e72420ff35c00b27a34cb9937e902a8b810e2c88300c6f0a3b699d"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "h11-0.14.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/95/04/ff642e65ad6b90db43e668d70ffb6736436c7ce41fcc549f4e9472234127/h11-0.14.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:e3fe4ac4b851c468cc8363d500db52c2ead036020723024a109d37346efaa761"),
				},
			},
		},
		{
			ID:           "httpcore@1.0.7",
			Name:         "httpcore",
			Version:      "1.0.7",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "httpcore-1.0.7.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/6a/41/d7d0a89eb493922c37d343b607bc1b5da7f5be7e383740b4753ad8943e90/httpcore-1.0.7.tar.gz",
					Digests:  lockfileDigests("sha256:8551cb62a169ec7162ac7be8d4817d561f60e08eaa485234898414bb5a8a0b4c"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "httpcore-1.0.7-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/87/f5/72347bc88306acb359581ac4d52f23c0ef445b57157adedb9aee0cd689d2/httpcore-1.0.7-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:a3fff8f43dc260d5bd363d9f9cf1830fa3a458b332856f34282de498ed420edd"),
				},
			},
		},
		{
			ID:           "idna@3.10",
			Name:         "idna",
			Version:      "3.10",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "idna-3.10.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/f1/70/7703c29685631f5a7590aa73f1f1d3fa9a380e654b86af429e0934a32f7d/idna-3.10.tar.gz",
					Digests:  lockfileDigests("sha256:12f65c9b470abda6dc35cf8e63cc574b1c52b11df2c86030af0ac09b01b13ea9"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "idna-3.10-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/76/c6/c88e154df9c4e1a2a66ccf0005a88dfb2650c1dffb6f5ce603dfbd452ce3/idna-3.10-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3"),
				},
			},
		},
		{
			ID:           "iniconfig@2.0.0",
			Name:         "iniconfig",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "iniconfig-2.0.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/d7/4b/cbd8e699e64a6f16ca3a8220661b5f83792b3017d0f79807cb8708d33913/iniconfig-2.0.0.tar.gz",
					Digests:  lockfileDigests("sha256:2d91e135bf72d31a410b17c16da610a82cb55f6b0477d1a902134b24a455b8b3"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "iniconfig-2.0.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/ef/a6/62565a6e1cf69e10f5727360368e451d4b7f58beeac6173dc9db836a5b46/iniconfig-2.0.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:b6a85871a79d2e3b22d2d1b94ac2824226a63c6b741c88f7ae975f18b6778374"),
				},
			},
		},
		{
			ID:           "packaging@24.2",
			Name:         "packaging",
			Version:      "24.2",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "packaging-24.2.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/d0/63/68dbb6eb2de9cb10ee4c9c14a0148804425e13c4fb20d61cce69f53106da/packaging-24.2.tar.gz",
					Digests:  lockfileDigests("sha256:c228a6dc5e932d346bc5739379109d49e8853dd8223571c7c5b55260edc0b97f"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "packaging-24.2-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/88/ef/eb23f262cca3c0c4eb7ab1933c3b1f03d021f2c48f54763065b6f0e321be/packaging-24.2-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759"),
				},
			},
		},
		{
			ID:           "pluggy@1.5.0",
			Name:         "pluggy",
			Version:      "1.5.0",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "pluggy-1.5.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/96/2d/02d4312c973c6050a18b314a5ad0b3210edb65a906f868e31c111dede4a6/pluggy-1.5.0.tar.gz",
					Digests:  lockfileDigests("sha256:2cffa88e94fdc978c4c574f15f9e59b7f4201d439195c3715ca9e2486f1d0cf1"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "pluggy-1.5.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/88/5f/e351af9a41f866ac3f1fac4ca0613908d9a41741cfcf2228f4ad853b697d/pluggy-1.5.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:44e1ad92c8ca002de6377e165f3e0f1be63266ab4d554740532335b9d75ea669"),
				},
			},
		},
		{
			ID:           "sniffio@1.3.1",
			Name:         "sniffio",
			Version:      "1.3.1",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "sniffio-1.3.1.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/a2/87/a6771e1546d97e7e041b6ae58d80074f81b7d5121207425c964ddf5cfdbd/sniffio-1.3.1.tar.gz",
					Digests:  lockfileDigests("sha256:f4324edc670a0f49750a81b895f35c3adb843cca46f0530f79fc1babb23789dc"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "sniffio-1.3.1-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/e9/44/75a9c9421471a6c4805dbf2356f7c181a29c1879239abab1ea2cc8f38b40/sniffio-1.3.1-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2"),
				},
			},
		},
		{
			ID:           "socksio@1.0.0",
			Name:         "socksio",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "socksio-1.0.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/f8/5c/48a7d9495be3d1c651198fd99dbb6ce190e2274d0f28b9051307bdec6b85/socksio-1.0.0.tar.gz",
					Digests:  lockfileDigests("sha256:f88beb3da5b5c38b9890469de67d0cb0f9d494b78b106ca1845f96c10b91c4ac"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "socksio-1.0.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/37/c3/6eeb6034408dac0fa653d126c9204ade96b819c936e136c5e8a6897eee9c/socksio-1.0.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:95dc1f15f9b34e8d7b16f06d74b8ccf48f609af32ab33c608d08761c5dcbb1f3"),
				},
			},
		},
		{
			ID:           "tomli@2.0.1",
			Name:         "tomli",
			Version:      "2.0.1",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "tomli-2.0.1.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/c0/3f/d7af728f075fb08564c5949a9c95e44352e23dee646869fa104a3b2060a3/tomli-2.0.1.tar.gz",
					Digests:  lockfileDigests("sha256:de526c12914f0c550d15924c62d72abc48d6fe7364aa87328337a31007fe8a4f"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "tomli-2.0.1-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/97/75/10a9ebee3fd790d20926a90a2547f0bf78f371b2f13aa822c759680ca7b9/tomli-2.0.1-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:939de3e7a6161af0c887ef91b7d41a53e7c5a1ca976325f429cb46ea9bc30ecc"),
				},
			},
		},
		{
			ID:           "typing-extensions@4.12.2",
			Name:         "typing-extensions",
			Version:      "4.12.2",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "typing_extensions-4.12.2.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/df/db/f35a00659bc03fec321ba8bce9420de607a1d37f8342eee1863174c69557/typing_extensions-4.12.2.tar.gz",
					Digests:  lockfileDigests("sha256:1a7ead55c7e559dd4dee8856e3a88b41225abfe1ce8df57b7c13915fe121ffb8"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "typing_extensions-4.12.2-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/26/9f/ad63fc0248c5379346306f8668cda6e2e2e9c95e01216d2b8ffd9ff037d0/typing_extensions-4.12.2-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:04e5ca0351e0f3f85c6853954072df659d0d13fac324d0072316b67d7794700d"),
				},
			},
		},
		{
			ID:           "urllib3@2.2.3",
			Name:         "urllib3",
			Version:      "2.2.3",
			Relationship: ftypes.RelationshipIndirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "urllib3-2.2.3.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/ed/63/22ba4ebfe7430b76388e7cd448d5478814d3032121827c12a2cc287e2260/urllib3-2.2.3.tar.gz",
					Digests:  lockfileDigests("sha256:e7d814a81dad81e6caf2ec9fdedb284ecc9c73076b62654547cc64ccdcae26e9"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "urllib3-2.2.3-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/ce/d9/5f4c13cecde62396b0d3fe530a50ccea91e7dfc1ccf0e09c228841bb5ba8/urllib3-2.2.3-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:ca899ca043dcb1bafa3e262d73aa25c465bfb49e0bd9dd5d59f1d0acba2f8fac"),
				},
			},
		},
	}

	// add a root project
	uvNormalDeps = []ftypes.Dependency{
		{ID: "anyio@4.7.0", DependsOn: []string{"exceptiongroup@1.2.2", "idna@3.10", "sniffio@1.3.1", "typing-extensions@4.12.2"}},
		{ID: "httpcore@1.0.7", DependsOn: []string{"certifi@2024.12.14", "h11@0.14.0"}},
		{ID: "httpx@0.28.1", DependsOn: []string{"anyio@4.7.0", "certifi@2024.12.14", "httpcore@1.0.7", "idna@3.10", "socksio@1.0.0"}},
		{ID: "normal@0.1.0", DependsOn: []string{"httpx@0.28.1", "jsonpointer@3.0.0", "pytest@8.3.4", "requests@2.32.0"}},
		{ID: "pytest@8.3.4", DependsOn: []string{"colorama@0.4.6", "exceptiongroup@1.2.2", "iniconfig@2.0.0", "packaging@24.2", "pluggy@1.5.0", "tomli@2.0.1"}},
		{ID: "requests@2.32.0", DependsOn: []string{"certifi@2024.12.14", "charset-normalizer@2.1.1", "idna@3.10", "urllib3@2.2.3"}},
	}

	uvWorkspaceVirtual = []ftypes.Package{
		{ID: "a@0.1.0", Name: "a", Version: "0.1.0", Relationship: ftypes.RelationshipWorkspace},
		{ID: "b@0.1.0", Name: "b", Version: "0.1.0", Relationship: ftypes.RelationshipWorkspace},
		{ID: "pillow@11.0.0", Name: "pillow", Version: "11.0.0", Relationship: ftypes.RelationshipDirect},
		{ID: "requests@2.32.3", Name: "requests", Version: "2.32.3", Relationship: ftypes.RelationshipDirect},
	}

	uvWorkspaceVirtualDeps = []ftypes.Dependency{
		{ID: "a@0.1.0", DependsOn: []string{"requests@2.32.3"}},
		{ID: "b@0.1.0", DependsOn: []string{"pillow@11.0.0"}},
	}

	uvWorkspaceRooted = []ftypes.Package{
		{ID: "root@0.1.0", Name: "root", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{ID: "a@0.1.0", Name: "a", Version: "0.1.0", Relationship: ftypes.RelationshipWorkspace},
		{ID: "b@0.1.0", Name: "b", Version: "0.1.0", Relationship: ftypes.RelationshipWorkspace},
		{ID: "click@8.1.7", Name: "click", Version: "8.1.7", Relationship: ftypes.RelationshipDirect},
		{ID: "pillow@11.0.0", Name: "pillow", Version: "11.0.0", Relationship: ftypes.RelationshipDirect},
		{ID: "pytest@8.3.4", Name: "pytest", Version: "8.3.4", Relationship: ftypes.RelationshipDirect, Dev: true},
		{ID: "requests@2.32.3", Name: "requests", Version: "2.32.3", Relationship: ftypes.RelationshipDirect},
		{ID: "ruff@0.9.0", Name: "ruff", Version: "0.9.0", Relationship: ftypes.RelationshipDirect, Dev: true},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "idna@3.10", Name: "idna", Version: "3.10", Relationship: ftypes.RelationshipIndirect},
		{ID: "tomli@2.2.1", Name: "tomli", Version: "2.2.1", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "urllib3@2.2.3", Name: "urllib3", Version: "2.2.3", Relationship: ftypes.RelationshipIndirect},
	}

	uvWorkspaceRootedDeps = []ftypes.Dependency{
		{ID: "a@0.1.0", DependsOn: []string{"pytest@8.3.4", "requests@2.32.3"}},
		{ID: "b@0.1.0", DependsOn: []string{"pillow@11.0.0", "ruff@0.9.0"}},
		{ID: "pillow@11.0.0", DependsOn: []string{"idna@3.10"}},
		{ID: "pytest@8.3.4", DependsOn: []string{"colorama@0.4.6"}},
		{ID: "requests@2.32.3", DependsOn: []string{"urllib3@2.2.3"}},
		{ID: "root@0.1.0", DependsOn: []string{"a@0.1.0", "b@0.1.0", "click@8.1.7"}},
		{ID: "ruff@0.9.0", DependsOn: []string{"tomli@2.2.1"}},
	}
)

var (
	// uv_distributions.lock is generated by uv 0.9.30 in ghcr.io/astral-sh/uv:python3.12-bookworm-slim.
	// The project depends on packages from PyPI with an sdist only, a wheel only and both, two
	// versions of typing-extensions for different Python versions, a local sdist, a local wheel,
	// a package from a local find-links directory, and an sdist and a wheel by direct URL.
	uvDistributions = []ftypes.Package{
		{ID: "uv-distributions@0.1.0", Name: "uv-distributions", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{
			ID:           "docopt@0.6.2",
			Name:         "docopt",
			Version:      "0.6.2",
			Relationship: ftypes.RelationshipDirect,
			Digests:      lockfileDigests("sha256:49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491"),
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "docopt-0.6.2.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/a2/55/8f8cab2afd404cf578136ef2cc5dfb50baa1761b68c9da1fb1e4eed343c9/docopt-0.6.2.tar.gz",
					Digests:  lockfileDigests("sha256:49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491"),
				},
			},
		},
		{ID: "flpkg@0.1.0", Name: "flpkg", Version: "0.1.0", Relationship: ftypes.RelationshipDirect},
		{
			ID:           "idna@3.10",
			Name:         "idna",
			Version:      "3.10",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "idna-3.10.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/f1/70/7703c29685631f5a7590aa73f1f1d3fa9a380e654b86af429e0934a32f7d/idna-3.10.tar.gz",
					Digests:  lockfileDigests("sha256:12f65c9b470abda6dc35cf8e63cc574b1c52b11df2c86030af0ac09b01b13ea9"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "idna-3.10-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/76/c6/c88e154df9c4e1a2a66ccf0005a88dfb2650c1dffb6f5ce603dfbd452ce3/idna-3.10-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3"),
				},
			},
		},
		{
			ID:           "iniconfig@2.0.0",
			Name:         "iniconfig",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipDirect,
			Digests:      lockfileDigests("sha256:2d91e135bf72d31a410b17c16da610a82cb55f6b0477d1a902134b24a455b8b3"),
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "iniconfig-2.0.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/source/i/iniconfig/iniconfig-2.0.0.tar.gz",
					Digests:  lockfileDigests("sha256:2d91e135bf72d31a410b17c16da610a82cb55f6b0477d1a902134b24a455b8b3"),
				},
			},
		},
		{
			ID:           "localpkg@0.1.0",
			Name:         "localpkg",
			Version:      "0.1.0",
			Relationship: ftypes.RelationshipDirect,
			Digests:      lockfileDigests("sha256:80c4f6842e96165dacd7bc974fa9bd8d03b26ac5eb5d2b897fd39bd356511e47"),
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "localpkg-0.1.0.tar.gz",
					URL:      "../dist/localpkg-0.1.0.tar.gz",
					Digests:  lockfileDigests("sha256:80c4f6842e96165dacd7bc974fa9bd8d03b26ac5eb5d2b897fd39bd356511e47"),
				},
			},
		},
		{
			ID:           "localwhl@0.1.0",
			Name:         "localwhl",
			Version:      "0.1.0",
			Relationship: ftypes.RelationshipDirect,
			Digests:      lockfileDigests("sha256:028fd549c18a9cd0f33dc14cdcba5d856659a01ee71e64e3b994d3a077f48eb8"),
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "localwhl-0.1.0-py2.py3-none-any.whl",
					URL:      "../dist/localwhl-0.1.0-py2.py3-none-any.whl",
					Digests:  lockfileDigests("sha256:028fd549c18a9cd0f33dc14cdcba5d856659a01ee71e64e3b994d3a077f48eb8"),
				},
			},
		},
		{
			ID:           "pluggy@1.5.0",
			Name:         "pluggy",
			Version:      "1.5.0",
			Relationship: ftypes.RelationshipDirect,
			Digests:      lockfileDigests("sha256:44e1ad92c8ca002de6377e165f3e0f1be63266ab4d554740532335b9d75ea669"),
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "pluggy-1.5.0-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/py3/p/pluggy/pluggy-1.5.0-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:44e1ad92c8ca002de6377e165f3e0f1be63266ab4d554740532335b9d75ea669"),
				},
			},
		},
		{
			ID:           "six@1.16.0",
			Name:         "six",
			Version:      "1.16.0",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "six-1.16.0.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz",
					Digests:  lockfileDigests("sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "six-1.16.0-py2.py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl",
					Digests:  lockfileDigests("sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"),
				},
			},
		},
		{
			ID:           "tensorboard-plugin-wit@1.8.1",
			Name:         "tensorboard-plugin-wit",
			Version:      "1.8.1",
			Relationship: ftypes.RelationshipDirect,
			Digests:      lockfileDigests("sha256:ff26bdd583d155aa951ee3b152b3d0cffae8005dc697f72b44a8e8c2a77a8cbe"),
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "tensorboard_plugin_wit-1.8.1-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/e0/68/e8ecfac5dd594b676c23a7f07ea34c197d7d69b3313afdf8ac1b0a9905a2/tensorboard_plugin_wit-1.8.1-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:ff26bdd583d155aa951ee3b152b3d0cffae8005dc697f72b44a8e8c2a77a8cbe"),
				},
			},
		},
		{
			ID:           "typing-extensions@4.12.2",
			Name:         "typing-extensions",
			Version:      "4.12.2",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "typing_extensions-4.12.2.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/df/db/f35a00659bc03fec321ba8bce9420de607a1d37f8342eee1863174c69557/typing_extensions-4.12.2.tar.gz",
					Digests:  lockfileDigests("sha256:1a7ead55c7e559dd4dee8856e3a88b41225abfe1ce8df57b7c13915fe121ffb8"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "typing_extensions-4.12.2-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/26/9f/ad63fc0248c5379346306f8668cda6e2e2e9c95e01216d2b8ffd9ff037d0/typing_extensions-4.12.2-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:04e5ca0351e0f3f85c6853954072df659d0d13fac324d0072316b67d7794700d"),
				},
			},
		},
		{
			ID:           "typing-extensions@4.7.1",
			Name:         "typing-extensions",
			Version:      "4.7.1",
			Relationship: ftypes.RelationshipDirect,
			Distributions: []ftypes.Distribution{
				{
					Kind:     ftypes.DistributionKindSource,
					FileName: "typing_extensions-4.7.1.tar.gz",
					URL:      "https://files.pythonhosted.org/packages/3c/8b/0111dd7d6c1478bf83baa1cab85c686426c7a6274119aceb2bd9d35395ad/typing_extensions-4.7.1.tar.gz",
					Digests:  lockfileDigests("sha256:b75ddc264f0ba5615db7ba217daeb99701ad295353c45f9e95963337ceeeffb2"),
				},
				{
					Kind:     ftypes.DistributionKindBuilt,
					FileName: "typing_extensions-4.7.1-py3-none-any.whl",
					URL:      "https://files.pythonhosted.org/packages/ec/6b/63cc3df74987c36fe26157ee12e09e8f9db4de771e0f3404263117e75b95/typing_extensions-4.7.1-py3-none-any.whl",
					Digests:  lockfileDigests("sha256:440d5dd3af93b060174bf433bccd69b0babc3b15b1a8dca43789fd7f61514b36"),
				},
			},
		},
	}

	uvDistributionsDeps = []ftypes.Dependency{
		{
			ID: "uv-distributions@0.1.0",
			DependsOn: []string{
				"docopt@0.6.2",
				"flpkg@0.1.0",
				"idna@3.10",
				"iniconfig@2.0.0",
				"localpkg@0.1.0",
				"localwhl@0.1.0",
				"pluggy@1.5.0",
				"six@1.16.0",
				"tensorboard-plugin-wit@1.8.1",
				"typing-extensions@4.12.2",
			},
		},
	}
)

func lockfileDigests(d string) []digest.SourcedDigest {
	return []digest.SourcedDigest{
		{
			Digest: digest.Digest(d),
			Source: digest.SourceLockfile,
		},
	}
}
