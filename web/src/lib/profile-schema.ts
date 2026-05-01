import type { JSONSchema7 } from 'json-schema';

/**
 * JSON Schema for ZTP profile YAML files.
 * Drives tab-completion and inline validation in the Profile File Editor.
 */
export const profileSchema: JSONSchema7 = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'ZTP Profile',
  description: 'A zero-touch provisioning profile that defines the configuration delivered to a device.',
  type: 'object',
  properties: {
    name: {
      type: 'string',
      description: 'Unique profile identifier (lowercase letters, digits, dash, underscore).'
    },
    description: {
      type: 'string',
      description: 'Human-readable description shown in the UI profile picker.'
    },
    labels: {
      type: 'object',
      description: 'Arbitrary string tags for grouping in the UI and selector matching.',
      additionalProperties: { type: 'string' }
    },
    priority: {
      type: 'integer',
      description: 'Selector evaluation order — higher values are evaluated first. Profiles with equal priority break ties by name. Default is 0.',
      default: 0
    },
    selector: {
      type: 'object',
      description:
        'Auto-assign this profile to devices whose facts match. All non-empty constraints must match (logical AND). Omit to make the profile assignable only via explicit allowlist/token/manual assignment.',
      additionalProperties: false,
      properties: {
        match_labels: {
          type: 'object',
          description: 'facts.labels[k] == v equalities. All listed pairs must match.',
          additionalProperties: { type: 'string' }
        },
        match_model: {
          type: 'string',
          description: 'Regular expression matched against the device-reported model string.'
        },
        match_mac_oui: {
          type: 'array',
          description:
            'MAC OUI prefixes (first three octets, e.g. "dc:a6:32"). The selector matches if ANY reported MAC starts with ANY listed OUI.',
          items: { type: 'string' }
        },
        match_hostname: {
          type: 'string',
          description: 'Regular expression matched against the device hostname.'
        }
      }
    },
    payload: {
      type: 'object',
      description:
        'Provider configurations — each key activates a module delivered to the device at enrollment.',
      additionalProperties: false,
      properties: {
        ssh: {
          type: 'object',
          description: 'Install SSH authorized_keys for a user on the device.',
          additionalProperties: false,
          properties: {
            user: {
              type: 'string',
              description: "Unix user to add keys for. Defaults to 'root'.",
              default: 'root'
            },
            keys: {
              type: 'array',
              description: 'OpenSSH public-key lines to authorize.',
              items: { type: 'string' }
            },
            github_users: {
              type: 'array',
              description:
                'GitHub usernames — their keys are fetched from https://github.com/<user>.keys at enrollment time.',
              items: { type: 'string' }
            },
            github_api_url: {
              type: 'string',
              description:
                "Override the GitHub base URL (default 'https://github.com'). Useful for GitHub Enterprise.",
              default: 'https://github.com'
            }
          }
        },
        wifi: {
          type: 'object',
          description: 'Configure one or more Wi-Fi networks the device should join.',
          additionalProperties: false,
          properties: {
            networks: {
              type: 'array',
              description: 'Ordered list of Wi-Fi networks.',
              items: {
                type: 'object',
                required: ['ssid'],
                additionalProperties: false,
                properties: {
                  ssid: {
                    type: 'string',
                    description: 'Network SSID.'
                  },
                  password: {
                    type: 'string',
                    description: 'Network passphrase (sensitive — sealed before delivery).'
                  },
                  key_mgmt: {
                    type: 'string',
                    description: "Key management protocol.",
                    enum: ['WPA-PSK', 'WPA-EAP', 'NONE'],
                    default: 'WPA-PSK'
                  },
                  hidden: {
                    type: 'boolean',
                    description: "Set true for networks that don't broadcast their SSID.",
                    default: false
                  },
                  priority: {
                    type: 'integer',
                    description: 'wpa_supplicant/NetworkManager connection priority. Higher values are preferred.',
                    default: 0
                  }
                }
              }
            }
          }
        },
        cumulocity: {
          type: 'object',
          description:
            'Cumulocity IoT connection settings and per-device enrollment token issuance.',
          additionalProperties: false,
          properties: {
            url: {
              type: 'string',
              description: "Cumulocity tenant URL, e.g. 'https://example.cumulocity.com'. Falls back to C8Y_BASEURL env var."
            },
            tenant: {
              type: 'string',
              description: 'Cumulocity tenant ID. Falls back to C8Y_TENANT env var.'
            },
            external_id_prefix: {
              type: 'string',
              description: 'Prefix prepended to the device external ID when registering in Cumulocity.'
            },
            device_id_prefix: {
              type: 'string',
              description: 'Legacy alias for external_id_prefix.'
            },
            token_ttl: {
              type: 'string',
              description: "Lifetime of the issued enrollment token, e.g. '10m', '1h', '24h'.",
              default: '10m'
            },
            issuer: {
              type: 'object',
              description: 'Controls how per-device enrollment tokens are minted.',
              additionalProperties: false,
              properties: {
                mode: {
                  type: 'string',
                  description:
                    "Issuer mode: 'local' — ZTP holds C8Y credentials; 'remote' — mTLS sidecar (credentials never reach ZTP); 'static' — fixed token (INSECURE, test-only); '' — disable token minting.",
                  enum: ['local', 'remote', 'static', '']
                },
                credential_ref: {
                  type: 'string',
                  description:
                    'Name of a shared credential entry (configured in the desktop app) that provides base_url / tenant / username / password.'
                },
                base_url: {
                  type: 'string',
                  description: 'Cumulocity base URL override (local mode).'
                },
                tenant: {
                  type: 'string',
                  description: 'Cumulocity tenant ID override (local mode).'
                },
                username: {
                  type: 'string',
                  description: 'Cumulocity username (local mode).'
                },
                password: {
                  type: 'string',
                  description: 'Cumulocity password (local mode, sensitive).'
                },
                credentials_file: {
                  type: 'string',
                  description:
                    'Path to a go-c8y-cli credentials file on the server (local mode). Alternative to inline username/password.'
                },
                endpoint: {
                  type: 'string',
                  description: 'mTLS sidecar endpoint URL (remote mode).'
                },
                client_cert: {
                  type: 'string',
                  description: 'Path to the client TLS certificate file (remote mode).'
                },
                client_key: {
                  type: 'string',
                  description: 'Path to the client TLS private key file (remote mode).'
                },
                ca_cert: {
                  type: 'string',
                  description: 'Path to the CA certificate file used to verify the sidecar (remote mode).'
                },
                static_token: {
                  type: 'string',
                  description: 'Fixed enrollment token returned for every device (static mode, INSECURE).'
                }
              }
            }
          }
        },
        files: {
          type: 'object',
          description: 'Write arbitrary files to the device.',
          additionalProperties: false,
          properties: {
            files: {
              type: 'array',
              description: 'List of files to create or overwrite on the device.',
              items: {
                type: 'object',
                required: ['path'],
                additionalProperties: false,
                properties: {
                  path: {
                    type: 'string',
                    description: 'Absolute path where the file will be written on the device.'
                  },
                  mode: {
                    type: 'string',
                    description: "Unix file permissions in octal notation.",
                    default: '0644'
                  },
                  owner: {
                    type: 'string',
                    description: "File owner in 'user:group' format, e.g. 'root:root'."
                  },
                  contents: {
                    type: 'string',
                    description: 'Raw text file contents (sensitive — sealed before delivery).'
                  },
                  base64: {
                    type: 'string',
                    description:
                      'Base64-encoded file contents for binary or pre-encoded files (sensitive — sealed before delivery).'
                  }
                }
              }
            }
          }
        },
        hook: {
          type: 'object',
          description:
            'Run a shell script on the device after the rest of the bundle has been applied. The bundle signature is verified before execution.',
          additionalProperties: false,
          properties: {
            script: {
              type: 'string',
              description: 'Shell script body to execute (sensitive — sealed before delivery).'
            },
            interpreter: {
              type: 'string',
              description: "Script interpreter path.",
              default: '/bin/sh'
            }
          }
        },
        passwd: {
          type: 'object',
          description: 'Set or update user passwords on the device.',
          additionalProperties: false,
          properties: {
            users: {
              type: 'array',
              description: 'List of user password entries.',
              items: {
                type: 'object',
                required: ['name', 'password'],
                additionalProperties: false,
                properties: {
                  name: {
                    type: 'string',
                    description: 'Unix username.'
                  },
                  password: {
                    type: 'string',
                    description: 'New password for the user (sensitive — sealed before delivery).'
                  }
                }
              }
            }
          }
        }
      }
    }
  }
};
