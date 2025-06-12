# RAG 기반 코드 취약점 분석 시스템

이 시스템은 Retrieval-Augmented Generation (RAG)을 활용하여 코드의 취약점을 분석하는 도구입니다. Elasticsearch를 지식 베이스로 사용하고, Ollama를 통해 LLM을 활용합니다.

## 시스템 구조

1. **기능적 의미 추출**: 입력된 코드의 기능적 의미를 LLM을 통해 추출
2. **유사 취약점 검색**: 
   - BM25 알고리즘을 사용한 초기 검색
   - RRF(Reciprocal Rank Fusion)를 통한 후보 재정렬
3. **취약점 판단**: 검색된 유사 취약점 정보를 기반으로 LLM이 최종 판단

## 필요 조건

- Python 3.8 이상
- Elasticsearch 8.x
- Ollama
- 필요한 Python 패키지 (requirements.txt 참조)

## 설치 방법

1. 저장소 클론
```bash
git clone <repository-url>
cd <repository-name>
```

2. 가상환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
.\venv\Scripts\activate  # Windows
```

3. 필요한 패키지 설치
```bash
pip install -r requirements.txt
```

4. Elasticsearch 실행 확인
```bash
curl http://localhost:9200
```

5. Ollama 설치 및 실행
```bash
curl https://ollama.ai/install.sh | sh
ollama run qwen3:32b
```

## 사용 방법

### 1. 지식 베이스 구축
```bash
python index_knowledge.py
```

### 2. 취약점 분석 실행

기본 사용법:
```bash
python start.py '분석할_코드'
```

예시:
```bash
python start.py 'def process_input(user_input):\n    cmd = f"ls {user_input}"\n    os.system(cmd)'
```

### 명령줄 옵션

- `--disable-rag`: RAG 기능을 비활성화하고 LLM만 사용하여 분석
  ```bash
  python start.py --disable-rag '분석할_코드'
  ```

- `--help`: 도움말 메시지 표시
  ```bash
  python start.py --help
  ```

## 환경 설정

`config.py` 파일에서 다음 설정을 변경할 수 있습니다:

- `ELASTICSEARCH_HOST`: Elasticsearch 호스트 (기본값: "localhost")
- `ELASTICSEARCH_PORT`: Elasticsearch 포트 (기본값: 9200)
- `OLLAMA_HOST`: Ollama 호스트 (기본값: "http://localhost:11434")
- `MODEL_NAME`: 사용할 LLM 모델 (기본값: "qwen3:32b")

## 주의사항

- 코드에 줄바꿈이 있는 경우 `\n`을 사용하여 표현하세요.
- RAG 모드(기본)는 Elasticsearch의 취약점 데이터베이스를 활용하여 더 정확한 분석을 제공합니다.
- RAG 비활성화 모드는 LLM만을 사용하여 빠른 분석을 제공하지만, 정확도가 다소 낮을 수 있습니다. 