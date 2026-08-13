use crate::{ProbeSpec, RiskLevel, VulnClass};
use serde_json::json;

pub fn migrated_specs(product: &str) -> Vec<ProbeSpec> {
    let normalized = product.to_ascii_lowercase().replace('_', "-");
    let mut out = Vec::new();
    match normalized.as_str() {
        "anythingllm" => {
            out.push(ProbeSpec{id:"anythingllm.unauth".into(),product:"anythingllm".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/system/env-dump","/api/env-dump","/api/system","/api/system/check-token","/api/setup-complete","/api/v1/system","/.env"],"tag_prefix":"anythingllm"}),max_requests:8});
            out.push(ProbeSpec{id:"anythingllm.weak_password".into(),product:"anythingllm".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/request-token","body":{"username":"{user}","password":"{pass}"},"token_fields":["token","access_token","JWT","jwt"],"post_auth_paths":["/api/system","/api/system/env-dump","/api/workspace","/api/v1/admin/users"],"extra_credentials":[["admin","password"],["mintplexlabs","password"]]}),max_requests:12});
        }
        "chatgpt-next-web" => {
            out.push(ProbeSpec{id:"chatgpt-next-web.unauth".into(),product:"chatgpt-next-web".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/","/api/config","/api/openai","/api/openai/v1/models","/.env","/api/auth"],"tag_prefix":"chatgpt_next_web"}),max_requests:8});
            out.push(ProbeSpec{id:"chatgpt-next-web.weak_password".into(),product:"chatgpt-next-web".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/auth","body":{"password":"{pass}","code":"{pass}"},"token_fields":["token","access_token","status"],"post_auth_paths":["/api/config","/api/openai/v1/models"],"extra_credentials":[["","123456"],["","password"],["","admin"]]}),max_requests:10});
        }
        "dify" => {
            out.push(ProbeSpec{id:"dify.unauth".into(),product:"dify".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec!["CVE-2025-63387".into()],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/console/api/system-features","/console/api/setup","/v1/models","/console/api/apps"],"tag_prefix":"dify"}),max_requests:5});
            out.push(ProbeSpec{id:"dify.weak_password".into(),product:"dify".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/console/api/login","body":{"email":"{user}","password":"{pass}","language":"en-US"},"token_fields":["access_token","token","refresh_token"],"post_auth_paths":["/console/api/workspaces/current","/console/api/apps","/console/api/datasets"],"extra_credentials":[["admin@admin.com","admin"],["admin@example.com","admin123"]]}),max_requests:14});
            out.push(ProbeSpec{id:"dify.ssrf.file".into(),product:"dify".into(),vuln_class:VulnClass::Ssrf,risk_level:RiskLevel::L2,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/console/api/remote-files/upload","method":"POST","url_param":"url","body":{},"target_urls":["http://127.0.0.1/","http://localhost/"],"use_auth":true}),max_requests:3});
            out.push(ProbeSpec{id:"dify.sqli.apps".into(),product:"dify".into(),vuln_class:VulnClass::Sqli,risk_level:RiskLevel::L2,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/console/api/apps","method":"GET","param":"name","baseline":"test","payloads":["' OR '1'='1","'"],"use_auth":true}),max_requests:4});
        }
        "fastgpt" => {
            out.push(ProbeSpec{id:"fastgpt.unauth".into(),product:"fastgpt".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/systemConfig","/api/openapi","/api/v1/models","/api/getInitData","/api/common/system/getInitData"],"tag_prefix":"fastgpt"}),max_requests:6});
            out.push(ProbeSpec{id:"fastgpt.weak_password".into(),product:"fastgpt".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/support/user/account/loginByPassword","body":{"username":"{user}","password":"{pass}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/support/user/account/tokenLogin","/api/core/dataset/list","/api/support/openapi/list"]}),max_requests:12});
        }
        "flowise" => {
            out.push(ProbeSpec{id:"flowise.unauth".into(),product:"flowise".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec!["CVE-2026-56270".into()],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/v1/loginmethod","/api/v1/credentials","/api/v1/chatflows","/api/v1/apikeys"],"expand_params":{"organizationId":["","1","default"]},"tag_prefix":"flowise"}),max_requests:8});
            out.push(ProbeSpec{id:"flowise.weak_password".into(),product:"flowise".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/v1/auth/login","body":{"username":"{user}","password":"{pass}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/v1/credentials","/api/v1/chatflows","/api/v1/apikeys"]}),max_requests:12});
            out.push(ProbeSpec{id:"flowise.idor.chatflows".into(),product:"flowise".into(),vuln_class:VulnClass::Idor,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:true,depends_on:vec!["flowise.weak_password".into()],entry:json!({"list":"/api/v1/chatflows","object":"/api/v1/chatflows/{id}","id_enum_max":5,"id_fields":["id","_id","chatflowId"],"use_auth":true}),max_requests:6});
            out.push(ProbeSpec{id:"flowise.idor.credentials".into(),product:"flowise".into(),vuln_class:VulnClass::Idor,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:true,depends_on:vec!["flowise.weak_password".into()],entry:json!({"list":"/api/v1/credentials","object":"/api/v1/credentials/{id}","id_enum_max":5,"id_fields":["id","_id"],"use_auth":true}),max_requests:6});
            out.push(ProbeSpec{id:"flowise.ssrf.fetch".into(),product:"flowise".into(),vuln_class:VulnClass::Ssrf,risk_level:RiskLevel::L2,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/api/v1/node-load-method/fetch","method":"POST","url_param":"url","body":{},"target_urls":["http://127.0.0.1/","http://localhost/"],"use_auth":true}),max_requests:3});
            out.push(ProbeSpec{id:"flowise.rce.proof".into(),product:"flowise".into(),vuln_class:VulnClass::Rce,risk_level:RiskLevel::L3,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/api/v1/node-load-method/customFunction","method":"POST","param":"javascriptFunction","proof_command":"echo aipocket-rce-proof","secret_commands":["printenv","cat /.env"],"body":{},"use_auth":true}),max_requests:2});
        }
        "langflow" => {
            out.push(ProbeSpec{id:"langflow.unauth".into(),product:"langflow".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/v1/flows","/api/v1/config","/api/v1/variables","/api/v1/credentials","/api/all-flows"],"tag_prefix":"langflow"}),max_requests:6});
            out.push(ProbeSpec{id:"langflow.weak_password".into(),product:"langflow".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/v1/login","body":{"username":"{user}","password":"{pass}"},"token_fields":["access_token","token","refresh_token"],"post_auth_paths":["/api/v1/flows","/api/v1/variables","/api/v1/credentials"]}),max_requests:12});
            out.push(ProbeSpec{id:"langflow.ssrf".into(),product:"langflow".into(),vuln_class:VulnClass::Ssrf,risk_level:RiskLevel::L2,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/api/v1/validate/code","method":"POST","url_param":"url","body":{},"target_urls":["http://127.0.0.1/","http://localhost/"],"use_auth":true}),max_requests:3});
            out.push(ProbeSpec{id:"langflow.rce".into(),product:"langflow".into(),vuln_class:VulnClass::Rce,risk_level:RiskLevel::L3,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/api/v1/validate/code","method":"POST","param":"code","proof_command":"echo aipocket-rce-proof","secret_commands":["printenv","cat /.env"],"body":{},"use_auth":false}),max_requests:2});
        }
        "librechat" => {
            out.push(ProbeSpec{id:"librechat.unauth".into(),product:"librechat".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/config","/api/endpoints","/api/health"],"tag_prefix":"librechat"}),max_requests:4});
            out.push(ProbeSpec{id:"librechat.weak_password".into(),product:"librechat".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/auth/login","body":{"email":"{user}","password":"{pass}","username":"{user}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/keys","/api/endpoints"]}),max_requests:12});
            out.push(ProbeSpec{id:"librechat.idor.keys".into(),product:"librechat".into(),vuln_class:VulnClass::Idor,risk_level:RiskLevel::L1,cve_ids:vec!["CVE-2026-31942".into()],requires_auth:true,depends_on:vec!["librechat.weak_password".into()],entry:json!({"list":"/api/keys","object":"/api/keys/{id}","id_enum_max":5,"id_fields":["id","_id","userId","keyId"],"use_auth":true}),max_requests:6});
        }
        "litellm" => {
            out.push(ProbeSpec{id:"litellm.unauth".into(),product:"litellm".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/v1/models","/health","/key/list","/config/list"],"tag_prefix":"litellm_unauth"}),max_requests:5});
            out.push(ProbeSpec{id:"litellm.weak_password".into(),product:"litellm".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"hybrid","bearer_paths":["/key/list","/config/list"],"login":"/sso/key/generate","body":{"username":"{user}","password":"{pass}"},"password_prefix":"litellm_","token_fields":["key","token","api_key"],"post_auth_paths":["/key/list","/config/list"]}),max_requests:16});
            out.push(ProbeSpec{id:"litellm.idor.keys".into(),product:"litellm".into(),vuln_class:VulnClass::Idor,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:true,depends_on:vec!["litellm.weak_password".into()],entry:json!({"list":"/key/list","object":"/key/info?key={id}","id_enum_max":5,"id_fields":["token","key","key_name","id"],"use_auth":true}),max_requests:6});
        }
        "sub2api" => {
            out.push(ProbeSpec{id:"sub2api.weak_password".into(),product:"sub2api".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/v1/auth/login","body":{"email":"{user}","password":"{pass}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/v1/models","/api/v1/keys","/api/v1/users"],"extra_credentials":[["admin","admin"],["admin","123456"],["admin","admin123"]]}),max_requests:12});
        }
        "newapi" => {
            out.push(ProbeSpec{id:"newapi.weak_password".into(),product:"newapi".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/user/login","body":{"username":"{user}","password":"{pass}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/status","/api/user/self","/api/channel"],"extra_credentials":[["root","123456"],["admin","123456"],["admin","admin123"]]}),max_requests:12});
        }
        "oneapi" => {
            out.push(ProbeSpec{id:"oneapi.weak_password".into(),product:"oneapi".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/user/login","body":{"username":"{user}","password":"{pass}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/status","/api/user/self"],"extra_credentials":[["root","123456"],["admin","123456"]]}),max_requests:10});
        }
        "lobechat" => {
            out.push(ProbeSpec{id:"lobechat.unauth".into(),product:"lobechat".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/config","/api/client/config","/api/env","/api/market"],"tag_prefix":"lobechat"}),max_requests:5});
        }
        "openrouter" => {
            out.push(ProbeSpec{id:"openrouter.unauth".into(),product:"openrouter".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/v1/models","/v1/models","/api/v1/auth/key","/api/v1/keys","/api/config","/.env","/health"],"tag_prefix":"openrouter"}),max_requests:8});
            out.push(ProbeSpec{id:"openrouter.weak_password".into(),product:"openrouter".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"hybrid","bearer_paths":["/api/v1/keys","/api/v1/auth/key","/api/config"],"login":"/api/auth/login","body":{"email":"{user}","password":"{pass}"},"token_fields":["token","access_token","key"],"post_auth_paths":["/api/v1/keys","/api/v1/auth/key"]}),max_requests:12});
        }
        "openwebui" => {
            out.push(ProbeSpec{id:"openwebui.unauth".into(),product:"openwebui".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/api/config","/api/v1/models","/ollama/api/tags","/api/models"],"tag_prefix":"openwebui"}),max_requests:5});
            out.push(ProbeSpec{id:"openwebui.weak_password".into(),product:"openwebui".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"login_json","login":"/api/v1/auths/signin","body":{"email":"{user}","password":"{pass}"},"token_fields":["token","access_token"],"post_auth_paths":["/api/v1/auths/","/api/v1/models","/api/v1/configs/export","/api/config"],"extra_credentials":[["admin@localhost","admin"],["admin@admin.com","admin"]]}),max_requests:14});
            out.push(ProbeSpec{id:"openwebui.idor.users".into(),product:"openwebui".into(),vuln_class:VulnClass::Idor,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:true,depends_on:vec!["openwebui.weak_password".into()],entry:json!({"list":"/api/v1/users/","object":"/api/v1/users/{id}","id_enum_max":5,"id_fields":["id","user_id"],"use_auth":true}),max_requests:6});
            out.push(ProbeSpec{id:"openwebui.ssrf.tools".into(),product:"openwebui".into(),vuln_class:VulnClass::Ssrf,risk_level:RiskLevel::L2,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"path":"/api/v1/tools/","method":"POST","url_param":"url","body":{"name":"probe"},"target_urls":["http://127.0.0.1/","http://localhost/"],"use_auth":true}),max_requests:3});
        }
        "portkey" => {
            out.push(ProbeSpec{id:"portkey.unauth".into(),product:"portkey".into(),vuln_class:VulnClass::UnauthRead,risk_level:RiskLevel::L0,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"paths":["/v1/models","/v1/health","/health","/v1/config","/api/config","/v1/keys","/.env"],"tag_prefix":"portkey"}),max_requests:8});
            out.push(ProbeSpec{id:"portkey.weak_password".into(),product:"portkey".into(),vuln_class:VulnClass::WeakPassword,risk_level:RiskLevel::L1,cve_ids:vec![],requires_auth:false,depends_on:vec![],entry:json!({"auth_style":"hybrid","bearer_paths":["/v1/keys","/v1/config","/api/config"],"login":"/v1/auth/login","body":{"email":"{user}","password":"{pass}","username":"{user}"},"token_fields":["token","access_token","api_key","key"],"post_auth_paths":["/v1/keys","/v1/config","/api/config"]}),max_requests:14});
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_inventory_is_complete() {
        let products = [
            "anythingllm",
            "chatgpt-next-web",
            "dify",
            "fastgpt",
            "flowise",
            "langflow",
            "librechat",
            "litellm",
            "lobechat",
            "openrouter",
            "openwebui",
            "portkey",
        ];
        assert_eq!(
            products
                .iter()
                .map(|p| migrated_specs(p).len())
                .sum::<usize>(),
            35
        );
    }
}
