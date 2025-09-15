first# zt-attack-bot

**For use only on systems you own or are authorized to test.**  
Simple password-only login tester (dictionary attempts) against `POST /auth/login`.

## Install
```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt


목적]

이 봇은 “뚫기”가 아니라, 비밀번호/OTP/레이트리밋 등의 방어정책이 제대로 작동하는지를 계측합니다.

실험은 반드시 본인 소유의 로컬/테스트 환경에서만 수행하세요.

[봇이 알려주는 것 (핵심 인사이트)]

온라인 공격 성공 가능성(베이스라인)

wordlist 모드에서 약한 비밀번호가 얼마나 빨리 맞춰지는지(또는 전혀 못 맞추는지)를 보여줍니다.

‘비번만’ 환경이 얼마나 취약한지, 레이트리밋/락이 없을 때와 있을 때의 차이를 수치로 비교할 수 있습니다.

OTP 방어의 실효성

otp-invalid-spray: 랜덤 6자리 코드 분사 시 대부분이 400/429로 막히는지, **200(성공)**이 없어야 정상인지 확인합니다.

otp-replay: 같은 타임스텝의 OTP 코드 재사용을 서버가 거부하는지(정책 검증).

otp-window: OTP 시간 허용창(valid_window) 설정에 따라 prev/now/next 코드의 허용 여부가 정책대로 동작하는지 확인합니다.

레이트리밋/락 정책 품질

429 비율, 락이 걸리기까지 걸린 시도 수, 락 지속시간(서버 로그 기반) 등으로 남용 억제 능력을 평가할 수 있습니다.

성능 영향(지연/사용성)

각 모드에서 p50/p95 지연(응답시간)을 측정해, MFA 도입 후 로그인 시간 비용을 수치화할 수 있습니다.

운영 안전성/정책 누락 탐지

MFA 단계 세션(mfa_uid) 처리 오류, 코드 재사용 허용 등 정책 구멍을 조기에 발견할 수 있습니다.

[모드별 해석]
A) wordlist (비번만 테스트)

CSV의 status_200이 1 이상이면 “비번이 맞았다”는 뜻(서버가 MFA를 요구하면 실제 로그인 완료는 아님).

first_success_s(첫성공초), attempts(시도수)로 ‘취약 비번’의 노출 정도와 레이트리밋 효과를 보세요.

강한 비밀번호/락 정책이 있으면 status_200=0, 대부분 401/429가 됩니다.

B) otp-invalid-spray (잘못된 6자리 OTP 분사)

기대값: status_200≈0, status_400/429가 대부분.

429 비율이 높고 빠르게 나타나면, 레이트리밋/락이 잘 작동하는 것입니다.

200이 보인다면 정책/코드 결함 가능성(시크릿 유출, 검증 버그, 너무 넓은 valid_window 등)을 의심해야 합니다.

C) otp-replay (동일 타임스텝 코드 재사용)

기대값: 첫 시도는 200, 두 번째는 400/429(재사용 거부).

두 번째도 200이면 재사용 취약. 동일 타임스텝 코드는 1회만 허용하도록 서버를 수정하세요.

D) otp-window (시간 허용창 검증)

valid_window=0이면 now만 200, prev/next는 거부가 정상.

valid_window=1이면 prev/now/next 모두 200일 수도 있음(편의↑, 보안↓). 정책 의도와 일치하는지 확인하세요.

[CSV 필드(주요 항목)]

mode(모드): 실행 모드(wordlist/otp-invalid-spray/otp-replay/otp-window)

started_at/ended_at: 실행 시작/종료 시각(로컬 시간)

base/user: 대상 API/계정 식별

concurrency/qps/duration_*: 부하 조건

attempts: 총 시도 수

status_200/400/401/403/429, status_other: 응답 코드 분포

first_success_s / first_password / first_note: wordlist 모드의 첫 성공 관련

otp_code / first_status / second_status: otp-replay 모드의 코드/응답

status_prev/now/next: otp-window 모드의 스텝별 응답

latency_p50_ms / latency_p95_ms: 응답 지연 분포(성능 영향)

[연구/보고용 지표 예시]

ASR(침해 성공률): 성공 계정 수 / 총 대상 계정 수

TTFS(첫 성공까지 시간) / MATFS(첫 성공까지 시도 수)

429 비율, 락 발동률, 락 지속시간(서버 로그와 함께)

지연 p50/p95 비교(베이직 vs OTP vs 디바이스+OTP)

OTP 보안비트 근사: v=0일 때 p≈1/10^6 ≈ 2^-20 → 비번 성공확률과 곱해 총 성공확률 산출

[기대되는 “좋은” 결과 패턴]

wordlist: 강한 비번+락 정책에서 status_200=0, 대부분 401/429

otp-invalid-spray: 200=0, 429가 빠르게 우세

otp-replay: first=200, second≠200

otp-window: 정책대로 prev/now/next의 200/비-200이 일관

[문제 징후]

otp 모드에서 status_200 등장(시크릿 노출/버그 가능성)

otp-replay에서 두 번째도 200(재사용 허용)

otp-window에서 예상보다 넓은 허용 범위

invalid-spray에서 429가 거의 발생하지 않음(레이트리밋 미적용)

[추가 권장 점검]

MFA 단계 세션 만료시간 짧게(예: 2~3분)

동일 타임스텝 코드 재사용 금지(last_used_step 저장)

계정/IP/세션 단위 레이트리밋+락, 점진 지연

백업코드 1회성/해시 보관, 시도 제한

서버/클라이언트 시간 동기(NTP)

가능하면 WebAuthn(피싱 저항)도 별도 실험 추가

[재현성/보고 팁]

같은 부하 조건(concurrency, qps, duration)으로 A/B 모드를 반복 실행해 평균/분산을 함께 보고

CSV를 기반으로 표/그래프(ASR, TTFS, 429%)를 생성

서버 로그의 코릴레이션 ID로 클라이언트 시도와 매칭

[안전 고지]

이 도구는 방어 측정용입니다.

본인 소유/허가된 환경에서만 사용하세요.