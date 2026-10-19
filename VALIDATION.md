# Проверки v1.7.11-dsg2-rc3

**Предварительный выпуск. Подтверждена только указанная ниже ограниченная
стендовая проверка; свежая production-приёмка не выполнена.**

Текущий код зафиксирован как freeze-v6. Для него прошли 200 локальных тестов
без ошибок и пропусков; отдельно прошли пять тестов bootstrap с подставным
curl и тестовыми архивами. Эти пять тестов не обращались к сети и не запускали
настоящий setup. Проверены передача аргументов и отказ до setup при неверном
SHA256, ошибке загрузки, выходе пути из архива и символической ссылке.

Freeze-v4 и его результаты сохранены отдельно: он проходил 159 локальных
тестов. Перечисленные ниже завершённые VM-сценарии относятся к v4 и не
переносятся автоматически на изменённый путь v6. Freeze-v5 проходил 168
локальных тестов; его полный режим затем остановился на смене банка A/B.
Текущий v6 также проверен компиляцией 37 Python-файлов и синтаксисом
9 shell-файлов. Manifest из 74 записей:
`8d00efbd26640a78d3e822ea3bb4e3e679be3de588ab49d2bae1416309563803`. Неизменённый bootstrap
сохраняет тот же проверенный SHA256.

## Результаты freeze-v4 на изолированном стенде

| Сценарий | Результат и граница |
|---|---|
| Настоящая холодная загрузка при незавершённой активации | PASS: прежние файлы запрета уже отсутствовали; новая защита сохранилась, запуск запрещён, nDPI-правил нет, чужие правила сохранены |
| Восстановление после теста защиты загрузки | PASS: использован откат продукта, прежние запреты, библиотека, службы и исходные журналы восстановлены; новые временные защитные файлы убраны |
| Намеренный отказ проверки приложения | PASS как отрицательный сценарий: установка вернула ожидаемый код 1, достигнут намеренный отказ, откат восстановил прежние запреты; nDPI-правил нет, чужой контрольный объект firewall сохранён |
| Повторная активация после этого отката | PASS, 294 секунды: три локальных слоя, строгий HTTPS, сохранение чужой политики и исходного журнала |
| Повторный полный режим после отдельного контроля первого отказа | PASS, код `0`, 243,70 секунды на QEMU TCG; три слоя, HTTPS и исходный журнал подтверждены |
| Первый `rollback-upgrade` после принятого обновления | PASS, ожидаемый код `20`, 1406,93 секунды на QEMU TCG; исходные файлы и запреты восстановлены, загруженный модуль сохранён до отдельной перезагрузки |
| Повтор `rollback-upgrade` | PASS, ожидаемый код `20`, 26,37 секунды на QEMU TCG; отдельная перезагрузка по-прежнему требуется |
| Новый цикл после завершённого отката | **FAILED_ATTEMPT_PRESERVED**: внешний код `78`; worker 3/3 принят, общий lifecycle-журнал не завершён |
| Отдельный сетевой профиль и его откат | Не приняты в цепочке v4; текущие результаты v6 приведены отдельно ниже |
| Свежая последовательная приёмка на production-серверах и реальных клиентских путях | **Не выполнена** |

Это изолированная QEMU VM с Ubuntu 22.04 / `6.8.0-87-generic` и подготовленным
известным состоянием приостановленной legacy-установки. Она не является
побайтовой копией production-серверов. Для прежней идентичности использован
исправленный rc2-модуль с изменённым только ELF build-id; опасный прежний
бинарник vendor в этом сценарии не запускался. 294 секунды — длительность успешной
операции, а не отдельного непрерывного наблюдения. Этот результат не
доказывает непрерывную работу, устойчивость под пиковой нагрузкой или
отсутствие любых отложенных ошибок. Остальные сценарии не считаются принятыми
до записи их итоговых результатов.

### Первая попытка повторного полного режима

Первая попытка `full-repeat` завершилась кодом `1` за 398 секунд. Проверка
приложения выполняла строгий HTTPS-запрос к Google и получила `curl 28`:
тайм-аут 20 секунд, 0 полученных байт. Транзакция продукта имеет
`rolled_back=true`. Последующие сценарии цепочки автоматически не запускались.

Эта попытка сохранена как отказ; она не засчитывается в PASS и сама по себе
не устанавливает причину тайм-аута или дефект продукта. Отдельные read-only
проверки HTTPS и состояния VM прошли. После них один точный повтор
сценария завершился кодом `0` за 243,70 секунды с отдельной положительной
приёмкой. Он не заменяет исходную запись об отказе. Текущие результаты v6 и подтверждённое выключение стенда приведены ниже.

### Первый завершённый rollback-upgrade

Откат после принятого обновления завершился ожидаемым кодом `20` за
1406,93 секунды (23 минуты 27 секунд) на QEMU TCG. Это измерение стенда,
а не прогноз длительности на production. Подтверждены восстановление
прежнего модуля на диске и защитных файлов hold90, отсутствие nDPI-правил,
сохранение чужой политики и возврат файлов к состоянию перед обновлением.

Исправленный модуль остался загружен: livepatch не выгружался принудительно.
Код `20` означает необходимость отдельной перезагрузки для возврата исходной
идентичности модуля в памяти. Это ожидаемый промежуточный результат отката,
а не ошибка и не удаление первоначальной vendor-установки. Повтор отката
завершился ожидаемым кодом `20` за 26,37 секунды на QEMU TCG и засчитан
как успешный тест такого результата. Это не превращает код `20` в
подтверждение полностью восстановленного состава модулей в памяти.
Новый цикл v4 затем завершился отказом, описанным ниже; отдельный сетевой
сценарий в цепочке v4 не был принят.

### Отказ нового цикла v4 и изменение freeze-v5

Новый цикл v4 завершился внешним кодом `78` вместо ожидаемого `0` за
388,90 секунды на QEMU TCG. Worker сохранил положительную локальную приёмку
трёх слоёв и строгого HTTPS. Однако финальный `lifecycle.seal` не завершил
снимок: `apt-mark` получил ошибку переименования файла кэша APT с ENOENT
при конкурентной работе APT Daily. Внешний журнал сохранил ошибку и
преждевременные строки «ГОТОВО». Поэтому вся операция не засчитана как PASS;
успешный worker не подменяет завершение lifecycle.

Freeze-v5 меняет четыре файла: `lifecycle.py` читает APT без записи общих
кэшей, `setup_ru.py` выводит итоговый успех после успешного завершения
журнала; `test_apt_readonly.py` и `test_setup_lifecycle.py` проверяют эти
условия. 168/168 локальных тестов, 35 Python-файлов и 9 shell-файлов прошли
проверки; ошибок и пропусков нет. Manifest freeze-v5:
`32ba4882dc4ce7f66cc88606295fe3f41f5a62ffbf6b2ff6fa99bb8bc842e7cc`.

## Сохранённые результаты freeze-v5

| Сценарий | Статус |
|---|---|
| Лабораторное завершение только доказанного журнала операции v4 отдельным исходником v5 без замены исходного baseline | PASS во второй попытке, 44,78 секунды; первая остановка проверки сохранена, причина неизвестна |
| Полный режим v5 | **FAILED_ATTEMPT_PRESERVED**: код `78`, 51,92 секунды; штатная смена банка A/B была отклонена прежней точной проверкой |

## Текущая цепочка VM для freeze-v6

| Сценарий | Статус |
|---|---|
| Полный режим v6 | PASS, код `0`, 255,10 секунды на QEMU TCG: три слоя, строгий HTTPS, проверка приложения, чужие правила и исходный журнал подтверждены |
| Отдельный сетевой профиль v6 | PASS, код `0`, 88,67 секунды; все 15 заданных sysctl точны, `network_unchanged=true`, три слоя прошли |
| Откат обновления и сетевого профиля — одна команда, две проверки; внешний тестовый лимит 2250 секунд | PASS, ожидаемый код `20`, 1443,42 секунды на QEMU TCG; 227/227 шагов, файлы, 15 сетевых значений и поколение возвращены |
| Повтор отката v6 | PASS, ожидаемый код `20`, 78,82 секунды; все повторные проверки исходного состояния прошли |
| Новый цикл v6 | PASS, код `0`, 426,07 секунды; before/after точно архивированы, новый legacy-baseline и учёт собственных пакетов созданы, три слоя и HTTPS приняты |
| Финальная проверка и остановка VM | PASS: исходники из 74 файлов и установленный код точны к freeze-v6; штатное выключение, QEMU exit 0, базовый образ неизменен |

Лимит 2250 секунд относится к ожиданию лабораторного сценария; он не является
оценкой времени production или заявлением о новом runtime-лимите продукта.
Подготовленное лабораторное завершение только журнала — узкое действие над
доказанной операцией. Оно не объявляется автоматическим восстановлением
произвольной production-системы. Пять команд и шесть итоговых проверок новой цепочки прошли; финальное
чтение и штатное выключение стенда также подтверждены. Исходные отказы v4 остаются отдельными фактами.

Во второй попытке отдельный исходник v5 завершил только журнал ранее
доказанной операции v4 за 44,78 секунды. Исходный before сохранился точно,
pending удалён штатным завершением, установленная библиотека осталась v4.
Runtime-файлы, правила, службы, значения и пакеты не менялись; сохранены
точные raw-снимки проверки до и после. Первая попытка остановилась на
предварительной проверке с кодом `1`; причина **UNKNOWN**. Исходного raw-
сравнения этой первой попытки нет, поэтому изменение таймером или другим
процессом ей не приписывается. Отдельная диагностика позже показала точное
совпадение правил; это не доказывает причину прежней остановки.

Основная матрица v6 завершила **пять фактических команд и шесть
проверяемых результатов**: full, tune, rollback-upgrade, повтор rollback-upgrade
и новый цикл. Единственная команда rollback-upgrade после tune проверяет
одновременно возврат обновления и возврат сетевого профиля; обе проверки
ссылаются на один и тот же фактический запуск `v6_rollback_after_tune`.
Это один откат. Лабораторное завершение прежнего журнала и финальная
остановка VM учитываются отдельно от этих пяти команд.

Исходные неудачные проверки стенда сохранены отдельно: два ранних сценария
проверки загрузки завершились кодом 1 из-за ошибочных предположений теста.
Отдельная проверка с доказательствами из журнала завершилась кодом 0 и
подтвердила запрет запуска. Эти исходные отказы не удалены и не переименованы
в PASS. Намеренный отказ приложения также сохраняется как ожидаемый код 1,
а успешным результатом этого сценария считается доказанный откат.

`REVIEW3_VALIDATION.json` фиксирует хеши кода freeze-v6, исторические freeze-v4/v5, ссылки и хеши локальных
подтверждений и завершённые сценарии. Метаданные окончательного
публичного архива и загрузчика формируются отдельно: хеш исходного freeze
не следует выдавать за хеш архива после обновления документации.

## Отказ v5 на смене банка и узкое исправление v6

Полный режим v5 завершился кодом `78` вместо `0` за 51,92 секунды на
QEMU TCG. Две отдельные read-only выборки подтвердили одинаковую политику
после нормализации только имён банков A/B: порядок правил, чужие правила
и места подключения совпали. Из управляемых файлов отличался только
`domain-generation.env` с ACTIVE другого банка; исходный отказ сохранён в
`evidence-index-v5-bank-rotation-refusal.json` и не засчитан как PASS.
После него остальные сценарии v5 не запускались.

Freeze-v6 принимает такой переход только при строгом доказательстве:
файл поколения имеет root-владельца и режим 0600, его текст и хеш совпадают,
замена только ACTIVE восстанавливает исходный хеш, критические входные
списки не изменились, содержимое и порядок правил, места подключения и
чужая политика совпадают. Произвольная ротация DNS-адресов, изменение
политики или административное редактирование под это исключение не попадают.
Снимок поколения и firewall берётся под ограниченной по времени общей
блокировкой vendor. Исходные lifecycle before/after и их digest сохраняются.

Rollback отдельно записывает доказанное происхождение поколения в
progress/firewall/completed и добавляет его в область восстановления с
проверкой исходной копии и владельца, даже когда before и after совпали.
На продолжении доказательство перепроверяется; firewall допускает только
точное состояние до или после записанного шага. Нормализация банков не
заменяет эту проверку. Блокировка удерживается от согласованного снимка до
возврата hold90 и остановки guard, затем отпускается перед долгим возвратом
firewall и пакетными операциями.

Локальные тесты v6 прошли 200/200 без ошибок и пропусков, включая 36 тестов
rollback с 12 новыми сценариями ротации. Проверены прерывания после шага
firewall и после возврата поколения, повтор завершённого отката и отказы
при изменении proof, владельца, списков, исходного digest или чужих правил.
Повторный полный режим v6 принят: код `0`, 255,10 секунды на QEMU TCG.
Подтверждены три слоя, очереди NFQUEUE 0/1, строгий HTTPS и проверка
приложения, отсутствие новых ошибок ядра, чужие правила и исходный
baseline с прежним SHA256. Это длительность операции, не отдельное
непрерывное наблюдение.

Отдельный tune принят: код `0`, 88,67 секунды; все 15 заданных значений
sysctl совпали с фактическими, контроль сети и три слоя прошли. До tune
поколение уже совпадало с immutable before; дополнительного apply для
подготовки этого условия не было. Теперь фактические исходные условия
проверки отката подтверждены: before == after, current != after и
product_bank_proof=true. Raw-снимки и хеш выполненного тестового сценария
зафиксированы в `legacy22-v6-extra-generation-restore-preconditions.json`.

Общий rollback завершился ожидаемым кодом `20` за 1443,42 секунды
(24 минуты 3 секунды) на QEMU TCG. Один фактический запуск подтвердил обе
проверки: возврат обновления и сетевого профиля. Восстановлены исходные
файлы, hold90, все 15 изменённых сетевых значений и точное исходное
поколение; пройдены 227/227 шагов firewall. nDPI-правил нет, чужой
контрольный объект сохранён, исходный journal digest не подменён.
Хеш выполненного тестового сценария совпадает с сохранённым; проверка
поколения выполняется до записи accepted receipt.

Загруженный исправленный livepatch сохранён. Код `20` требует отдельной
перезагрузки для возврата исходной идентичности в памяти и не означает
удаление первоначальной vendor-установки. Повтор отката также принят с
ожидаемым кодом `20` за 78,82 секунды. Новый цикл принят с кодом `0` за
426,07 секунды: прежние before/after архивированы без изменений, новый
baseline имеет вид legacy-upgrade, учёт собственных пакетов начат заново;
три слоя, строгий HTTPS и проверка приложения прошли. Все длительности
относятся к QEMU TCG. Финальное чтение подтвердило 74 файла исходников и
установленный код относительно freeze-v6, отсутствие pending и тестовых
правил, чистый dpkg audit и отсутствие новых ошибок ядра. Точная проверка
поколения прошла и после общего отката, и после его повтора.

VM штатно выключена: QEMU завершился с кодом 0, serial подтвердил power
down. Базовый образ сохранил размер, mtime и SHA256
`3fc9e0492b4b9295d5f10e53030c706b7f2ba1e1ca51edce09ed15a3b04c1683`;
тестовый overlay сохранён. Это лабораторное завершение, а не подтверждение
публикации GitHub или production-приёмки. Итог:
`legacy22-v6-integration-summary.json`, финальное чтение:
`legacy22-v6-final-readback.json`.

## Граница проверки при внезапной потере питания

Проверенный cold-boot activation fence подтверждает запрет запуска
незавершённой активации в испытанном сценарии. Он не доказывает полное
восстановление после внезапной потери питания.

В зафиксированном runtime `lifecycle.save` заменяет файлы before/after и
связанных журналов хода/завершения атомарно, но без `fsync`. Новые marker,
защитные файлы hold90 и activation fence сохраняются с `fsync`. Атомарная
замена имени сама по себе не доказывает сохранность всех данных и
метаданных после аварийной потери питания.

При продолжении после прерывания процесса проверяется точное состояние
шага. Полнота журналов, доказанное происхождение записей и автоматическое
продолжение после потери питания отдельно не подтверждены. Независимый
узкий review не выявил подтверждённого P1 повторного включения старого nDPI;
это не доказательство отсутствия всех сбоев восстановления и не обещание
неизбежного безопасного отказа во всех power-loss-сценариях.

В `REVIEW3_VALIDATION.json` зафиксированы
`power_loss_recovery_tested=false` и `automatic_recovery_guaranteed=false`.
Это известное ограничение предварительного выпуска; production-приёмка
остаётся неподтверждённой. Замороженный runtime в рамках документирования
этого ограничения не менялся.

## Границы поддерживаемого переноса

Перенос поддерживает только строго известную ds-guard 1.7.11 с существующей
защитной приостановкой nDPI. Неизвестная legacy-версия, посторонний защитный
файл и ds-guard 2.x отклоняются. Загруженный livepatch не выгружается
принудительно: при иной идентичности сначала записывается исправленный
модуль на диск, возвращается код 20, затем требуется отдельная перезагрузка
и повтор той же команды. Ошибки ядра запрещают активацию; только известная
старая ошибка allocator допускает ограниченную подготовку на диске.

До повторного применения и приёмки трёх слоёв не обещается сохранение
временной DNS/NFQUEUE-фильтрации через перезагрузку. Защита незавершённой
активации не превращает этот промежуток в принятый режим фильтрации.

`rollback-upgrade` возвращает состояние непосредственно перед данным
обновлением, включая прежнюю приостановку. Исходное состояние до самого
первого vendor-скрипта неизвестно и не восстанавливается по предположению.
Поэтому `disable` и `remove` для такого legacy-журнала не поддерживаются и
отказывают до изменений. Для новой установки с полным исходным журналом
режимы full/kernel/tune/guard/check/status/disable/remove остаются
поддерживаемыми; их ранее полученные стендовые результаты ниже явно
отделены от нового набора rc3.

## Выпуск и production

`v1.7.11-dsg1` остаётся отозванным. Стабильный bootstrap в main остаётся
отключённым. Будущий rc3 публикуется только как предварительный выпуск;
его отдельный candidate.sh закрепляет SHA256 конкретного архива. Наличие
такого кандидата или одной команды установки не означает production-приёмку.
IPv6-фильтрация, произвольное оборудование, пиковая нагрузка и длительное
непрерывное наблюдение этими результатами не подтверждены.

## Исторические результаты до rc3

Ниже сохранён прежний отчёт без подмены его результатов текущими. Упоминания
73 тестов, rc1 и rc2 относятся к тем снимкам кода. Они дают историю ремонта
allocator и проверки новых установок, но не заменяют свежую приёмку
изменённого legacy-пути текущего freeze-v6.

### Historical allocator repair candidate — not a production release

The previous `v1.7.11-dsg1` is withdrawn. Its short acceptance windows missed
delayed KFENCE reports in the upstream realloc callback. Historical observations
remain in HISTORICAL_DSG1_VALIDATION.md and do not approve this candidate.

The actual original callback reproducibly fails ASan when growing 2048 bytes to
4096 bytes. The patched callback passed 794 ASan/UBSan cases, including growth,
shrinkage, calloc overflow, allocation/metadata failures and metadata cleanup.
Seventy-three compatibility, preservation, ownership, recovery, package-gate,
selection, restoration and boot-fallback tests pass, with no skipped tests in
the isolated root-capable local check. The compatibility
gate now refuses activation after an existing kernel fault in the current boot.

Modules compile for all four listed kernel/OS pairs. The Ubuntu 22.04 build
uses an isolated official Ubuntu 22.04 container, GCC 12.3.0 and exact
6.8.0-87.88~22.04.1 headers. No production source tree is overwritten.

The final native allocator harness passed 686 cases on each of three isolated
VM kernels: Ubuntu 6.8.0-147, custom XanMod 7.0 and custom XanMod 7.2. It uses
the actual kernel krealloc/XArray/vmalloc implementation, including atomic
packet context and a vmalloc allocation larger than kmalloc's limit. KFENCE
sampling was set to 1 ms in the isolated VMs only.

Completed isolated TLS traffic checks:
- 6.8.0-147-generic: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `a0fbde3481b0c36f5269c6a9d9c23a63a1d8a2250fdd20fb95222f21b19d2454`.
- 7.0.12-x64v2-dsg1-xanmod1: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `ece7def533a032fe3edc292e0be58d30b4cc5a6a58018ca942c453a5e59e8822`.
- 7.2.9-x64v3-dsg1-xanmod1: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `b899f08aa1865084c1b855238a2d1428ceb93889a940fd0279a1678b54683ee7`.
- 6.8.0-87-generic: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `ea53ae99f1b3bfed0de20a83230bed25654585f15185dff2bc46616baa8a892d`.

The final candidate passed repeated installation on custom XanMod 7.0. An
intentional failing application-health command triggered rollback: scoped files,
previously active services and foreign firewall rules were verified, followed
by successful three-layer payload checks. The final 6.8.0-147 / 7.0 / 7.2
binaries were checked after a new boot with matching loaded ELF build-id. The
Ubuntu 22.04 / 6.8.0-87 binary passed fresh installation and a subsequent cold
boot, matching loaded identity and all three filtering layers again. The first
cold-boot probe ran before service readiness and failed; that original result
is retained. A separate readiness-aware probe passed after startup completed. Ubuntu
22.04 VM preparation initially missed wireless-regdb; that dependency was
installed before the kernel boot and module acceptance. No production system
was used for this repair's build or runtime validation.

The corrected module has not been reaccepted on production. Existing production
nDPI packet matching remains held after the old allocator fault; independent
Suricata/DNS filtering was retained. No new ready-to-install release is approved.
Longer observation, production-specific rollback/boot review and actual
application-path acceptance remain required before that status changes.

## Reversible setup and network profile

The Russian setup interface has separate full, kernel-only, tuning-only, guard,
plan, status, disable and removal modes. Kernel selection uses the pinned tested
catalog, OS, CPU intersection and known loaded-driver exclusions. It does not
reboot, change the saved boot entry or schedule unattended kernel upgrades.

The following full-install lifecycle observations concern the earlier rc1 code;
the package and recovery corrections below require separate updated acceptance.
On an isolated Ubuntu 24.04 VM, fresh full installation and repeated installation
passed local payload checks. Disable, repeated disable, verified resume and full
removal preserved the immutable first baseline, original package versions,
files, sysctls, boot choice, unrelated firewall rules and an unrelated file.
A subsequent cold boot confirmed no nDPI module or managed hooks remained.
Tuning-only installation/removal separately restored original file contents,
mode and group, sysctls, packages and service state without installing guard.
Manual content and ownership changes were refused instead of overwritten.

On Ubuntu 22.04, network-profile apply, explicit rollback, intentional failing
health command and timeout recovery passed. Timeout recovery stops the worker
control group before restoring state; three-layer payload checks passed again.

An initial helper-variable shadowing bug was fixed. Two test-harness failures
were preserved: sysctl whitespace normalization and expecting a temporary test
firewall rule to survive an earlier reboot. Independent baseline comparisons
passed after correcting those assertions. Stock Ubuntu loaded vga16fb/vgastate
even in headless QEMU; the XanMod binaries lack these drivers. The compatibility
gate is retained, automatic policy falls back to Ubuntu and explicit XanMod
refuses. Cleanup of a partial unaccepted kernel stage preserved original packages
and boot selection. These results do not cover arbitrary hardware or legacy
vendor installs that lack a trustworthy original-state journal.


Kernel-only preparation from an already running custom XanMod 7.0 to custom
XanMod 7.2 passed in a separate no-VGA fixture. No nDPI file or service was
installed; the running kernel and saved GRUB selection were preserved. Status
reported the prepared-but-not-running kernel. Removal restored the exact initial
package set and removed only the newly prepared kernel; the original boot
selection remained unchanged. The first assertion compared stripped command
output to a newline-terminated GRUB capture and failed; independent normalized
readback and subsequent removal passed. Fixture preparation explicitly selected
the already tested 7.0 kernel outside the installer; this does not bypass the
Ubuntu VGA compatibility refusal.

After successful removal, malformed generated test-footer syntax prevented the
last health probe and shutdown. A separate corrected job independently rechecked
package restoration, boot choice, absence of nDPI and kernel health before
shutting down the VM. The failed footer receipt is retained.

Machine-readable hashes and bounded results are in VALIDATION_EVIDENCE.json.

## Post-rc1 safety review

Review reproduced package ownership contamination: an administrator's later
package could enter the global before/after difference and removal plan. Private
dpkg logs now attribute new installed packages to one operation UUID. An incomplete
receipt stops lifecycle sealing. Disable retains the previously owned scope;
sysctl writes require matching worker receipts. Existing APT manual/auto marks
are preserved, and interrupted disable resumes until restoration is complete.

APT --no-upgrade was independently shown to allow dependency upgrades. An
invocation-scoped Pre-Install-Pkgs hook now refuses replacement, reinstall or
architecture changes of any already installed package before dpkg executes.
The direct dpkg path also checks archives. CLI package timeout is propagated
to the controller as TimeoutExpired, leaving recovery to systemd after it has
stopped the worker control group.

A delayed recovery timer was reproduced stopping a newer tuning worker and
deleting its pending marker. Recovery now checks the exact transaction under a
state lock, cancels only its own timer and conditionally clears its own pending
record. Symlinks and foreign recovery units are refused before writes; rollback
checks saved file ownership as well as content and mode.

These changes do not establish production acceptance. Concurrent administrator
writes to the same managed file during installation do not yet have complete
per-writer provenance; drift between operations is refused before mutation.
Old lifecycle journals without package provenance are refused, not silently
adopted. The one-command production bootstrap remains disabled.


## Isolated rc2 integration acceptance

The updated exact code hashes are recorded in REVIEW2_VALIDATION.json. On the
isolated Ubuntu 24.04 / custom XanMod 7.0 fixture, actual APT and dpkg installs
produced separate ownership receipts. A later administrator package survived
repeat installation, disable and removal. Both direct replacement and an
indirect dependency upgrade from a private local package repository were
refused by the real APT hook before dpkg changed the installed version.

Intentional health exit 17 restored the network profile. A delayed recovery
from that completed transaction left a newer worker PID and pending record
unchanged; the new worker completed successfully. A 120-second health timeout
triggered systemd OnFailure recovery, restoring all 15 measured sysctls and
cancelling the matching fallback timer. The first probe lacked conntrack in
the empty fixture and stopped before mutation; it is retained separately.
An initial identity probe used the wrong copy/readiness time ordering; its
failure is retained alongside a corrected check of the actual package-suite
copy interval, guest manifest, unchanged code hashes and exact receipt hashes.

Fresh full installation, repeat installation, disable, repeated disable,
verified resume and removal also passed on that fixture. Three local payload
rounds checked DNS policy, nDPI matching and Suricata blocking. The immutable
baseline, original packages/sysctls and boot choice were preserved. Removal
reported that the loaded livepatch still required a reboot; a separate new
boot confirmed its absence and no managed firewall hooks or kernel faults.

The updated kernel-only path also prepared custom XanMod 7.2 alongside the
running custom 7.0 kernel. Two exact kernel packages were attributed, no guard
was installed, the saved boot entry stayed unchanged and status returned 20.
Removal restored the original package set. This tests preparation and removal;
runtime module acceptance on 7.2 remains the separately versioned rc1 evidence.

This is bounded local acceptance, not production or load acceptance. The
production bootstrap stays disabled pending fresh server checks and review
of remaining limitations.
