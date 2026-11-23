-- CreateTable
CREATE TABLE "EmployeeKey" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "lobeUserId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "ssoSubject" TEXT,
    "gatewayKeyId" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "keyEnc" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" DATETIME
);

-- CreateIndex
CREATE UNIQUE INDEX "EmployeeKey_lobeUserId_key" ON "EmployeeKey"("lobeUserId");
