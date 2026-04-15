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
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "bandit",
        "PyGithub",
        "gitpython",
        "google-generativeai",
        "requests",
        "pydantic",
    ],
    entry_points={
        "console_scripts": [
            "security-agent=security_agent.cli:main",
        ],
    },
)