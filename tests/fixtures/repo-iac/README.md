# IaC の題材

`audit_grep.sh` の 0 節が「インフラの定義あり」と判定できるかと、17 節が資料 13 の観点を拾えるかを見る。
穴のある側（`Dockerfile`・`infra/main.tf`・`k8s/node-agent.yaml`・`k8s/deployment.yaml`・`cfn/database.yaml` の ReportsDb）と、
正しく作った側（`services/worker/Dockerfile`・`infra/hardened.tf`・`k8s/api-hardened.yaml`・`cfn/database.yaml` の ArchiveDb）を置いている。
パッケージの定義を持たないので、ロックファイルは対象外と出る。
動く構成ではない。値はすべて架空。
