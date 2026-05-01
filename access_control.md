# Управление доступом: AI Gateway и Row-Level Security

## 1. Архитектурный обзор

Гибридная интеллектуальная система интегрирована с учётной системой 1С и должна гарантировать, что каждый пользователь видит **ровно те документы и данные, к которым ему предоставлен доступ** в 1С — не больше и не меньше. Это достигается через двухуровневую архитектуру: **AI Gateway** на уровне запросов и **Row-Level Security (RLS)** на уровне данных.

---

## 2. AI Gateway

### 2.1 Роль и место в архитектуре

AI Gateway — это единственная точка входа между пользователем и всеми AI-компонентами системы (LLM, векторная база знаний, RAG-пайплайн). Ни один запрос не проходит к модели в обход шлюза.

```
                         ┌───────────────────────────────────────┐
                         │              AI Gateway               │
                         │                                       │
Пользователь / UI ──────►│  1. Аутентификация (JWT / OAuth2)    │
                         │  2. Авторизация (RBAC + ABAC)         │
                         │  3. Обогащение контекста ролью        │
                         │  4. Rate Limiting по роли             │
                         │  5. Аудит и логирование               │
                         │  6. Input Sanitization                │
                         │             │                         │
                         └─────────────┼─────────────────────────┘
                                       │
                  ┌────────────────────┼────────────────────┐
                  ▼                    ▼                     ▼
           [LLM Backend]      [Vector DB (RAG)]       [1С API]
           (Claude / GPT)     (только разреш.          (только разреш.
                               namespace'ы)             данные)
```

### 2.2 Процесс аутентификации и авторизации

**Шаг 1 — Проверка токена:**
```
POST /api/v1/query
Authorization: Bearer <JWT>

Gateway проверяет:
  - Подпись токена (RS256)
  - Срок действия (exp)
  - Отзыв токена (Redis blacklist)
```

**Шаг 2 — Извлечение утверждений (claims):**
```json
{
  "sub": "user-42",
  "email": "ivanov@company.ru",
  "1c_roles": ["HR_Manager", "Salary_Viewer"],
  "1c_org_unit": "OU=Бухгалтерия,DC=company,DC=ru",
  "data_scope": ["salary_dept_id:5", "contracts:own"],
  "iat": 1714000000,
  "exp": 1714003600
}
```

**Шаг 3 — Построение контекста запроса:**

Gateway преобразует JWT-утверждения в **контекст безопасности**, который прикрепляется к каждому запросу:

```python
security_context = SecurityContext(
    user_id="user-42",
    allowed_namespaces=["hr_dept_5", "contracts_own"],
    forbidden_fields=["employee_salary", "passport_data"],
    max_result_rows=100,
    audit_level=AuditLevel.FULL
)
```

### 2.3 RBAC (Role-Based Access Control)

Роли определены на уровне 1С и синхронизируются в Gateway через LDAP/AD:

| Роль 1С | Разрешённые namespace в RAG | Разрешённые таблицы 1С | Запрещённые поля |
|---------|----------------------------|------------------------|-----------------|
| `Employee` | `public_docs`, `my_docs` | Только свои записи | Зарплаты коллег, HR-данные |
| `HR_Manager` | `hr_docs`, `public_docs` | Все сотрудники своего отдела | Данные других отделов |
| `Accountant` | `finance_docs`, `public_docs` | Финансовые регистры | Персональные данные |
| `Director` | Все namespace | Все таблицы | — |
| `Auditor` | Все namespace (read-only) | Все таблицы (read-only) | — |

---

## 3. Row-Level Security (RLS)

### 3.1 Принцип работы RLS

Row-Level Security — механизм, встроенный в слой данных, который автоматически фильтрует строки таблицы в зависимости от контекста безопасности текущего запроса. Даже если разработчик забудет добавить WHERE-условие в запрос, RLS-политика обрежет результат до разрешённых строк.

### 3.2 RLS на уровне векторной базы данных (RAG)

Каждый документ при индексации получает **метаданные доступа**:

```json
{
  "chunk_id": "doc-1234-chunk-7",
  "text": "Оклад Иванова И.И. составляет...",
  "metadata": {
    "source": "1c_salary_register",
    "owner_user_id": "user-42",
    "allowed_roles": ["HR_Manager", "Director", "Auditor"],
    "allowed_org_units": ["OU=HR"],
    "classification": "CONFIDENTIAL",
    "created_at": "2025-01-15"
  }
}
```

При каждом RAG-запросе фильтр применяется **до** семантического поиска:

```python
def retrieve_with_rls(query: str, security_ctx: SecurityContext) -> list[Chunk]:
    # RLS-фильтр применяется на уровне metadata filtering векторной БД
    rls_filter = {
        "$and": [
            {"metadata.allowed_roles": {"$in": security_ctx.user_roles}},
            {"metadata.allowed_org_units": {"$in": security_ctx.org_units}}
        ]
    }

    results = vector_db.similarity_search(
        query=query,
        filter=rls_filter,          # ← RLS отрабатывает здесь
        k=10
    )
    return results
```

**Критически важно**: фильтрация выполняется **до** передачи чанков в LLM. Модель физически не получает тексты документов, к которым у пользователя нет доступа.

### 3.3 RLS на уровне базы данных 1С

При обращении к 1С через API Gateway использует контекст безопасности для формирования запросов с явными ограничениями:

```sql
-- Запрос формируется AI Gateway, а не пользователем
-- Параметры подставляются из проверенного SecurityContext
SELECT
    doc.Ref, doc.Date, doc.Number, doc.Amount
FROM
    Document.SalesOrder AS doc
WHERE
    -- RLS-условие: только документы разрешённых контрагентов
    doc.Counterparty IN (
        SELECT cp.Ref FROM Catalog.Counterparties cp
        WHERE cp.ResponsibleManager = :current_user_id  -- из JWT
    )
    AND doc.Organization = :user_org_unit               -- из JWT
    AND doc.Posted = TRUE
```

В PostgreSQL-совместимых СУБД это реализуется через нативные политики RLS:

```sql
-- Политика для таблицы документов 1С (если используется PostgreSQL)
CREATE POLICY user_documents_policy ON documents
    FOR SELECT
    USING (
        organization_id = current_setting('app.org_unit_id')::uuid
        AND (
            responsible_user_id = current_setting('app.user_id')::uuid
            OR current_setting('app.user_role') IN ('Director', 'Auditor')
        )
    );

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
```

---

## 4. Сквозная схема: как система гарантирует изоляцию доступа

```
┌──────────────────────────────────────────────────────────────────┐
│                    Запрос пользователя                           │
│          "Покажи договоры с ООО Альфа за 2024 год"               │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  AI Gateway: Аутентификация + Авторизация                        │
│  ✓ JWT валиден                                                   │
│  ✓ Роль: Accountant (только свои контрагенты)                    │
│  → SecurityContext: {allowed_contractors: [id1, id2, id3]}       │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  RAG: Семантический поиск с RLS-фильтром                         │
│  Запрос к векторной БД: "договоры ООО Альфа"                     │
│  + фильтр: metadata.allowed_roles CONTAINS "Accountant"          │
│  + фильтр: metadata.contractor_id IN [id1, id2, id3]             │
│                                                                   │
│  Найдено: 3 чанка (договоры ООО Альфа, где user — ответственный) │
│  Отфильтровано: 12 чанков (договоры других менеджеров)            │
└─────────────────────────────┬────────────────────────────────────┘
                              │ Только 3 разрешённых чанка
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LLM: Генерация ответа                                           │
│  Контекст: [3 разрешённых чанка]                                 │
│  Системный промпт: "Отвечай ТОЛЬКО на основе предоставленных     │
│  документов. Не выдумывай данные."                               │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Output Guard: Финальная проверка ответа                         │
│  ✓ PII-проверка пройдена                                         │
│  ✓ Ответ не содержит данных о других контрагентах                │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
                    Пользователь получает ответ
                    только по своим договорам
```

---

## 5. Аудит и мониторинг доступа

Каждое обращение логируется в неизменяемый журнал:

```json
{
  "timestamp": "2025-04-22T10:15:32Z",
  "user_id": "user-42",
  "user_role": "Accountant",
  "query": "договоры ООО Альфа 2024",
  "retrieved_chunks": ["doc-789-chunk-1", "doc-790-chunk-3"],
  "filtered_chunks_count": 12,
  "llm_tokens_used": 1842,
  "response_hash": "sha256:a3f9...",
  "rls_policy_applied": "accountant_contractor_scope",
  "ip_address": "192.168.1.45",
  "session_id": "sess-0ef3a1"
}
```

Аномалии, требующие расследования:
- Пользователь запрашивает данные несуществующих контрагентов (попытка перебора)
- Резкий рост числа запросов от одной учётной записи
- Запросы в нерабочее время
- Попытки доступа к отфильтрованным namespace'ам
