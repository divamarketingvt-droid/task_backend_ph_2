// src/routes/integrationTokenRoutes.js
// Managing integration API tokens — logged-in Admin / SuperAdmin (normal JWT login).
// Mounted at /api/integrations/tokens behind authenticate + scope + permissions.
import express from "express";
import { authorize } from "../middleware/role.js";
import {
  createIntegrationToken,
  listIntegrationTokens,
  revokeIntegrationToken,
  regenerateIntegrationToken,
  deleteIntegrationToken,
} from "../controllers/integrationTokenController.js";

const router = express.Router();

router.use(authorize("Admin", "SuperAdmin"));

router.get("/", listIntegrationTokens);
router.post("/", createIntegrationToken);
router.post("/:id/revoke", revokeIntegrationToken);
router.post("/:id/regenerate", regenerateIntegrationToken);
router.delete("/:id", deleteIntegrationToken);

export default router;
