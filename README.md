# 🔥 FireWall Migrator Pro

## להורדת EXE מוכן — 3 שלבים

### שלב 1 — צור Repository ב-GitHub
1. כנס ל-[github.com/new](https://github.com/new)
2. שם: `firewall-migrator`
3. **Public** (חינמי) או Private
4. לחץ **Create repository**

### שלב 2 — העלה את הקוד
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/firewall-migrator.git
git push -u origin main
```

### שלב 3 — הורד את ה-EXE
1. כנס ל-**Actions** tab ב-GitHub repo שלך
2. רואה "Build Windows EXE" — לחץ עליו
3. לחץ **Run workflow** → **Run workflow**
4. המתן ~5 דקות
5. לחץ על ה-run שהושלם → **Artifacts** → הורד **FirewallMigratorPro-Windows**
6. חלץ ZIP → לחץ פעמיים על **FirewallMigratorPro.exe** ✅

---

## שימוש
לחיצה כפולה על ה-EXE → הדפדפן נפתח → בחר מיגרציה → בצע

## מיגרציות נתמכות
- **FortiGate → FortiGate** — שדרוג בין גרסאות FortiOS
- **CheckPoint → FortiGate** — המרת אובייקטים, פוליסות, NAT, Routes
