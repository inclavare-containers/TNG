pub mod egress;
pub mod ingress;

pub const ENVOY_DUMMY_CERT: &'static str = include_str!("servercert.pem");
pub const ENVOY_DUMMY_KEY: &'static str = include_str!("serverkey.pem");

pub const ENVOY_LISTENER_SOCKET_OPTIONS: &'static str = r#"
    - description: SO_KEEPALIVE
      int_value: 1
      level: 1
      name: 9
      state: STATE_PREBIND
    - description: TCP_KEEPIDLE
      int_value: 30
      level: 6
      name: 4
      state: STATE_PREBIND
    - description: TCP_KEEPINTVL
      int_value: 10
      level: 6
      name: 5
      state: STATE_PREBIND
    - description: TCP_KEEPCNT
      int_value: 5
      level: 6
      name: 6
      state: STATE_PREBIND
"#;

pub const ENVOY_HTTP2_CONNECT_WRAPPER_STREAM_IDLE_TIMEOUT: &'static str = "3600s"; // 1 hour

pub const ENVOY_L7_RESPONSE_BODY_DENIED: &'static str = "This service is secured by TNG secure session and you must establish the connection via TNG.\n\nIf this is an unexpected behavior, add path matching rules to `decap_from_http.allow_non_tng_traffic_regexes` option.";

pub const ENVOY_L7_RESPONSE_BODY_INJECT_TAG_HEAD: &'static str = r#"
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com?plugins=forms,typography"></script>
		<script src="https://unpkg.com/unlazy@0.11.3/dist/unlazy.with-hashing.iife.js" defer init></script>
		<script type="text/javascript">
			window.tailwind.config = {
				darkMode: ['class'],
				theme: {
					extend: {
						colors: {
							border: 'hsl(var(--border))',
							input: 'hsl(var(--input))',
							ring: 'hsl(var(--ring))',
							background: 'hsl(var(--background))',
							foreground: 'hsl(var(--foreground))',
							primary: {
								DEFAULT: 'hsl(var(--primary))',
								foreground: 'hsl(var(--primary-foreground))'
							},
							secondary: {
								DEFAULT: 'hsl(var(--secondary))',
								foreground: 'hsl(var(--secondary-foreground))'
							},
							destructive: {
								DEFAULT: 'hsl(var(--destructive))',
								foreground: 'hsl(var(--destructive-foreground))'
							},
							muted: {
								DEFAULT: 'hsl(var(--muted))',
								foreground: 'hsl(var(--muted-foreground))'
							},
							accent: {
								DEFAULT: 'hsl(var(--accent))',
								foreground: 'hsl(var(--accent-foreground))'
							},
							popover: {
								DEFAULT: 'hsl(var(--popover))',
								foreground: 'hsl(var(--popover-foreground))'
							},
							card: {
								DEFAULT: 'hsl(var(--card))',
								foreground: 'hsl(var(--card-foreground))'
							},
						},
					}
				}
			}
		</script>
		<style type="text/tailwindcss">
			@layer base {
				:root {
					--background: 0 0% 100%;
--foreground: 240 10% 3.9%;
--card: 0 0% 100%;
--card-foreground: 240 10% 3.9%;
--popover: 0 0% 100%;
--popover-foreground: 240 10% 3.9%;
--primary: 240 5.9% 10%;
--primary-foreground: 0 0% 98%;
--secondary: 240 4.8% 95.9%;
--secondary-foreground: 240 5.9% 10%;
--muted: 240 4.8% 95.9%;
--muted-foreground: 240 3.8% 46.1%;
--accent: 240 4.8% 95.9%;
--accent-foreground: 240 5.9% 10%;
--destructive: 0 84.2% 60.2%;
--destructive-foreground: 0 0% 98%;
--border: 240 5.9% 90%;
--input: 240 5.9% 90%;
--ring: 240 5.9% 10%;
--radius: 0.5rem;
				}
				.dark {
					--background: 240 10% 3.9%;
--foreground: 0 0% 98%;
--card: 240 10% 3.9%;
--card-foreground: 0 0% 98%;
--popover: 240 10% 3.9%;
--popover-foreground: 0 0% 98%;
--primary: 0 0% 98%;
--primary-foreground: 240 5.9% 10%;
--secondary: 240 3.7% 15.9%;
--secondary-foreground: 0 0% 98%;
--muted: 240 3.7% 15.9%;
--muted-foreground: 240 5% 64.9%;
--accent: 240 3.7% 15.9%;
--accent-foreground: 0 0% 98%;
--destructive: 0 62.8% 30.6%;
--destructive-foreground: 0 0% 98%;
--border: 240 3.7% 15.9%;
--input: 240 3.7% 15.9%;
--ring: 240 4.9% 83.9%;
				}
			}
		</style>
    "#;

pub const ENVOY_L7_RESPONSE_BODY_INJECT_TAG_BODY: &'static str = r#"
    <div id="security-bar" class="fixed top-0 left-0 w-full py-2 text-red-50 font-semibold text-center bg-red-500 flex justify-center items-center px-4 z-50">
      <div class="flex items-center space-x-2">
        <p id="security-description" class="text-sm"></p>
        <button id="info-button" class="bg-white bg-opacity-20 px-2 py-1 rounded-lg text-xs hover:bg-opacity-50 whitespace-nowrap">详细</button>
      </div>
    </div>
    <div id="modal" class="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center hidden z-50 px-10">
      <div class="bg-card p-6 rounded-lg max-w-5xl w-full mx-4 md:mx-0 relative shadow-lg border border-border">
        <button id="close-modal" class="absolute top-2 right-2 bg-destructive text-destructive-foreground px-2 py-1 rounded-lg text-xs hover:bg-destructive/80">关闭</button>
        <h2 class="text-lg font-semibold text-card-foreground mb-4">远程证明信息</h2>
        <div class="mb-4">
          <p class="text-sm text-card-foreground mb-1">目标服务地址：<span id="target-url" class="font-medium"></span></p>
          <p class="text-sm text-card-foreground mb-1">远程证明服务地址：<span id="trustee-url" class="font-medium"></span></p>
          <p class="text-sm text-card-foreground mb-1">启用的远程证明Policy：<span id="policy" class="font-medium"></span></p>
          <p class="text-sm text-card-foreground mb-1">远程证明状态：<span id="ra-status" class="font-medium"></span></p>
          <p class="text-sm text-card-foreground mb-1 hidden" id="msg-container">原因：<span id="msg" class="font-medium"></span></p>
        </div>
        
        <div id="claims-info">
          <div class="mt-4 bg-secondary p-4 rounded-lg">
            <h3 class="text-sm font-semibold text-secondary-foreground mb-2">CPU Attestation Claims</h3>
            <div class="overflow-y-auto max-h-40">            
              <table class="min-w-full text-xs text-secondary-foreground table-fixed">
                <thead>
                  <tr>
                    <th class="border-b border-border px-2 py-1 text-left w-1/2 break-words text-wrap">属性</th>
                    <th class="border-b border-border px-2 py-1 text-left w-1/2 break-words text-wrap">值</th>
                  </tr>
                </thead>
                <tbody id="cpu-claims"></tbody>
              </table>
            </div>
          </div>
          <div class="mt-4 bg-secondary p-4 rounded-lg">
            <h3 class="text-sm font-semibold text-secondary-foreground mb-2">GPU Attestation Claims</h3>
            <div class="overflow-y-auto max-h-40">
              <table class="min-w-full text-xs text-secondary-foreground table-fixed">
                <thead>
                  <tr>
                    <th class="border-b border-border px-2 py-1 text-left w-1/2 break-words text-wrap">属性</th>
                    <th class="border-b border-border px-2 py-1 text-left w-1/2 break-words text-wrap">值</th>
                  </tr>
                </thead>
                <tbody id="gpu-claims"></tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script type="text/javascript">
      document.body.style.marginTop = '2.5rem';

      const data = JSON.parse(String.raw`ATTESTATION_INFO_PLACEHOLDER`);

      const security_bar = document.getElementById('security-bar');
      const security_description = document.getElementById('security-description');
      const info_button = document.getElementById('info-button');
      const modal = document.getElementById('modal');
      const claims_info = document.getElementById('claims-info');
      const cpu_claims = document.getElementById('cpu-claims');
      const gpu_claims = document.getElementById('gpu-claims');
      const trustee_url_element = document.getElementById('trustee-url');
      const policy_element = document.getElementById('policy');
      const ra_status_element = document.getElementById('ra-status');
      const target_url_element = document.getElementById('target-url');
      const msg_element = document.getElementById('msg');
      const msg_container_element = document.getElementById('msg-container');


      security_description.textContent = data.is_secure 
        ? '🔐 安全 - 连接已加密：您访问的服务运行在经过验证的机密环境中' 
        : '🚨 不安全 - 您的连接不安全：服务端运行环境未通过验证';
      security_bar.classList.toggle('bg-red-500', !data.is_secure);
      security_bar.classList.toggle('bg-green-500', data.is_secure);
      document.body.classList.toggle('bg-zinc-500', !data.is_secure);
      ra_status_element.textContent = data.is_secure ? '通过' : '失败';
      claims_info.classList.toggle('hidden', !data.is_secure);
      msg_container_element.classList.toggle('hidden', data.is_secure);

      if (data.is_secure) {
        // Display CPU attestation claims
        cpu_claims.innerHTML = '';
        Object.entries(data.claims).forEach(([key, value]) => {
          if (!key.startsWith("tcb-status.tdx.x-nv-gpu")){
            const tr = document.createElement('tr');
            tr.innerHTML = `<td class="border-b border-border px-2 py-1 w-1/2 break-words break-all">${key}</td><td class="border-b border-border px-2 py-1 w-1/2 break-words break-all">${value}</td>`;
            cpu_claims.appendChild(tr);
          }
        });

        // Display GPU attestation claims
        gpu_claims.innerHTML = '';
        Object.entries(data.claims).forEach(([key, value]) => {
          if (key.startsWith("tcb-status.tdx.x-nv-gpu")){
            const tr = document.createElement('tr');
            tr.innerHTML = `<td class="border-b border-border px-2 py-1 w-1/2 break-words break-all">${key}</td><td class="border-b border-border px-2 py-1 w-1/2 break-words break-all">${value}</td>`;
            gpu_claims.appendChild(tr);
          }
        });
      } else {
        const fallback_msg = data.msg.replaceAll("\\n", "").replaceAll("\\\"","\"").replaceAll("\"", "")
        if (data.msg.search('InternalError') != -1 && data.msg.search('source:') != -1){
          const regex = /source:\s*\\"([^"]*)\\"/;
          const match = data.msg.match(regex);
          if (match) {
            msg_element.textContent = match[1];
          } else {
            msg_element.textContent = fallback_msg;
          }
        } else {
          msg_element.textContent = fallback_msg;
        }
      }

      // Set Trustee URL and policy
      trustee_url_element.textContent = data.trustee_url;
      policy_element.textContent = data.policy_ids;
      target_url_element.textContent = data.target_url;

      info_button.addEventListener('click', () => {
        modal.classList.remove('hidden');
      });

      const close_modal_button = document.getElementById('close-modal');
      close_modal_button.addEventListener('click', () => {
        modal.classList.add('hidden');
      });

      modal.addEventListener('click', (event) => {
        if (event.target === modal) {
          modal.classList.add('hidden');
        }
      });
    </script>
    <style>
      .bg-zinc-500 {
        background-color: #777;
      }
    </style>

    "#;
