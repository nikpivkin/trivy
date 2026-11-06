package uv_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/uv"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_uvAnalyzer_PostAnalyze(t *testing.T) {
	tests := []struct {
		dir  string
		want *analyzer.AnalysisResult
	}{
		// docker run --name uv --rm -it ghcr.io/astral-sh/uv@sha256:cd6887754aa1f907b0e95cc166ac6382d16a64a136df14d09ddb7375dfc1887e sh
		// uv init happy && cd happy
		// cat >> pyproject.toml <<EOF
		// [tool.uv]
		// constraint-dependencies = ["charset-normalizer==2.1.1", "tomli==2.0.1"]
		// exclude-newer = "2024-12-20T00:00:00Z"
		// EOF
		// uv add pluggy==1.5.0 requests==2.32.3
		// uv add --group test pytest==8.3.4
		{
			dir: "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Uv,
						FilePath: "uv.lock",
						Packages: types.Packages{
							{
								ID:           "happy@0.1.0",
								Name:         "happy",
								Version:      "0.1.0",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"pluggy@1.5.0",
									"pytest@8.3.4",
									"requests@2.32.3",
								},
							},
							{
								ID:           "pluggy@1.5.0",
								Name:         "pluggy",
								Version:      "1.5.0",
								Relationship: types.RelationshipDirect,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "pluggy-1.5.0.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/96/2d/02d4312c973c6050a18b314a5ad0b3210edb65a906f868e31c111dede4a6/pluggy-1.5.0.tar.gz",
										Digests:  lockfileDigests("sha256:2cffa88e94fdc978c4c574f15f9e59b7f4201d439195c3715ca9e2486f1d0cf1"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "pluggy-1.5.0-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/88/5f/e351af9a41f866ac3f1fac4ca0613908d9a41741cfcf2228f4ad853b697d/pluggy-1.5.0-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:44e1ad92c8ca002de6377e165f3e0f1be63266ab4d554740532335b9d75ea669"),
									},
								},
							},
							{
								ID:           "pytest@8.3.4",
								Name:         "pytest",
								Version:      "8.3.4",
								Relationship: types.RelationshipDirect,
								Dev:          true,
								DependsOn: []string{
									"colorama@0.4.6",
									"exceptiongroup@1.2.2",
									"iniconfig@2.0.0",
									"packaging@24.2",
									"pluggy@1.5.0",
									"tomli@2.0.1",
								},
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "pytest-8.3.4.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/05/35/30e0d83068951d90a01852cb1cef56e5d8a09d20c7f511634cc2f7e0372a/pytest-8.3.4.tar.gz",
										Digests:  lockfileDigests("sha256:965370d062bce11e73868e0335abac31b4d3de0e82f4007408d242b4f8610761"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "pytest-8.3.4-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/11/92/76a1c94d3afee238333bc0a42b82935dd8f9cf8ce9e336ff87ee14d9e1cf/pytest-8.3.4-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:50e16d954148559c9a74109af1eaf0c945ba2d8f30f0a3d3335edde19788b6f6"),
									},
								},
							},
							{
								ID:           "requests@2.32.3",
								Name:         "requests",
								Version:      "2.32.3",
								Relationship: types.RelationshipDirect,
								DependsOn: []string{
									"certifi@2024.12.14",
									"charset-normalizer@2.1.1",
									"idna@3.10",
									"urllib3@2.2.3",
								},
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "requests-2.32.3.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/63/70/2bf7780ad2d390a8d301ad0b550f1581eadbd9a20f896afe06353c2a2913/requests-2.32.3.tar.gz",
										Digests:  lockfileDigests("sha256:55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "requests-2.32.3-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"),
									},
								},
							},
							{
								ID:           "certifi@2024.12.14",
								Name:         "certifi",
								Version:      "2024.12.14",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "certifi-2024.12.14.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/0f/bd/1d41ee578ce09523c81a15426705dd20969f5abf006d1afe8aeff0dd776a/certifi-2024.12.14.tar.gz",
										Digests:  lockfileDigests("sha256:b650d30f370c2b724812bee08008be0c4163b163ddaec3f2546c1caf65f191db"),
									},
									{
										Kind:     types.DistributionKindBuilt,
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
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "charset-normalizer-2.1.1.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/a1/34/44964211e5410b051e4b8d2869c470ae8a68ae274953b1c7de6d98bbcf94/charset-normalizer-2.1.1.tar.gz",
										Digests:  lockfileDigests("sha256:5a3d016c7c547f69d6f81fb0db9449ce888b418b5b9952cc5e6e66843e9dd845"),
									},
									{
										Kind:     types.DistributionKindBuilt,
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
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "colorama-0.4.6.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/d8/53/6f443c9a4a8358a93a6792e2acffb9d9d5cb0a5cfd8802644b7b1c9a02e4/colorama-0.4.6.tar.gz",
										Digests:  lockfileDigests("sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44"),
									},
									{
										Kind:     types.DistributionKindBuilt,
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
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "exceptiongroup-1.2.2.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/09/35/2495c4ac46b980e4ca1f6ad6db102322ef3ad2410b79fdde159a4b0f3b92/exceptiongroup-1.2.2.tar.gz",
										Digests:  lockfileDigests("sha256:47c2edf7c6738fafb49fd34290706d1a1a2f4d1c6df275526b62cbb4aa5393cc"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "exceptiongroup-1.2.2-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/02/cc/b7e31358aac6ed1ef2bb790a9746ac2c69bcb3c8588b41616914eb106eaf/exceptiongroup-1.2.2-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:3111b9d131c238bec2f8f516e123e14ba243563fb135d3fe885990585aa7795b"),
									},
								},
							},
							{
								ID:           "idna@3.10",
								Name:         "idna",
								Version:      "3.10",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "idna-3.10.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/f1/70/7703c29685631f5a7590aa73f1f1d3fa9a380e654b86af429e0934a32f7d/idna-3.10.tar.gz",
										Digests:  lockfileDigests("sha256:12f65c9b470abda6dc35cf8e63cc574b1c52b11df2c86030af0ac09b01b13ea9"),
									},
									{
										Kind:     types.DistributionKindBuilt,
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
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "iniconfig-2.0.0.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/d7/4b/cbd8e699e64a6f16ca3a8220661b5f83792b3017d0f79807cb8708d33913/iniconfig-2.0.0.tar.gz",
										Digests:  lockfileDigests("sha256:2d91e135bf72d31a410b17c16da610a82cb55f6b0477d1a902134b24a455b8b3"),
									},
									{
										Kind:     types.DistributionKindBuilt,
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
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "packaging-24.2.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/d0/63/68dbb6eb2de9cb10ee4c9c14a0148804425e13c4fb20d61cce69f53106da/packaging-24.2.tar.gz",
										Digests:  lockfileDigests("sha256:c228a6dc5e932d346bc5739379109d49e8853dd8223571c7c5b55260edc0b97f"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "packaging-24.2-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/88/ef/eb23f262cca3c0c4eb7ab1933c3b1f03d021f2c48f54763065b6f0e321be/packaging-24.2-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759"),
									},
								},
							},
							{
								ID:           "tomli@2.0.1",
								Name:         "tomli",
								Version:      "2.0.1",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "tomli-2.0.1.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/c0/3f/d7af728f075fb08564c5949a9c95e44352e23dee646869fa104a3b2060a3/tomli-2.0.1.tar.gz",
										Digests:  lockfileDigests("sha256:de526c12914f0c550d15924c62d72abc48d6fe7364aa87328337a31007fe8a4f"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "tomli-2.0.1-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/97/75/10a9ebee3fd790d20926a90a2547f0bf78f371b2f13aa822c759680ca7b9/tomli-2.0.1-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:939de3e7a6161af0c887ef91b7d41a53e7c5a1ca976325f429cb46ea9bc30ecc"),
									},
								},
							},
							{
								ID:           "urllib3@2.2.3",
								Name:         "urllib3",
								Version:      "2.2.3",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Distributions: []types.Distribution{
									{
										Kind:     types.DistributionKindSource,
										FileName: "urllib3-2.2.3.tar.gz",
										URL:      "https://files.pythonhosted.org/packages/ed/63/22ba4ebfe7430b76388e7cd448d5478814d3032121827c12a2cc287e2260/urllib3-2.2.3.tar.gz",
										Digests:  lockfileDigests("sha256:e7d814a81dad81e6caf2ec9fdedb284ecc9c73076b62654547cc64ccdcae26e9"),
									},
									{
										Kind:     types.DistributionKindBuilt,
										FileName: "urllib3-2.2.3-py3-none-any.whl",
										URL:      "https://files.pythonhosted.org/packages/ce/d9/5f4c13cecde62396b0d3fe530a50ccea91e7dfc1ccf0e09c228841bb5ba8/urllib3-2.2.3-py3-none-any.whl",
										Digests:  lockfileDigests("sha256:ca899ca043dcb1bafa3e262d73aa25c465bfb49e0bd9dd5d59f1d0acba2f8fac"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			dir:  "testdata/broken-lock",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			a, err := uv.NewUvAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func lockfileDigests(d string) []digest.SourcedDigest {
	return []digest.SourcedDigest{
		{
			Digest: digest.Digest(d),
			Source: digest.SourceLockfile,
		},
	}
}
