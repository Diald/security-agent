from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="security-agent",
    version="0.1.0",
    author="Diald",
    author_email="dggam81@gmail.com",
    description="Multi-scanner security tool (Bandit, OSV, TruffleHog)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Diald/security-agent",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.10",
    install_requires=[
        "bandit>=1.7.5",
        "PyGithub>=1.59",
        "gitpython>=3.1.30",
        "google-generativeai>=0.3.0",
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "psycopg2-binary>=2.9.9",
        "sqlalchemy>=2.0.0",
        "Flask>=3.0.0",
        "flask-cors>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "security-agent=security_agent.cli:main",
        ],
    },
    keywords="security scanning sast sca secrets bandit osv trufflehog",
    project_urls={
        "Bug Tracker": "https://github.com/Diald/security-agent/issues",
        "Documentation": "https://github.com/Diald/security-agent/blob/main/README.md",
        "Source Code": "https://github.com/Diald/security-agent",
    },
)