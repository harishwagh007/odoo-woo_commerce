from odoo import http, fields
from odoo.http import request
import logging
import hmac
import hashlib
import base64

_logger = logging.getLogger(__name__)


class WooWebhookController(http.Controller):
    @http.route(
        "/woo/webhook",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
    )
    def woo_webhook(self):
        raw = request.httprequest.data or b""
        payload = request.httprequest.get_json(silent=True) or {}

        topic = request.httprequest.headers.get("X-WC-Webhook-Topic")
        source = request.httprequest.headers.get("X-WC-Webhook-Source")
        signature = request.httprequest.headers.get("X-WC-Webhook-Signature")

        Instance = request.env["woo.instance"].sudo()
        domain = [("active", "=", True)]
        if source:
            domain = [("shop_url", "ilike", source)]
        instance = Instance.search(domain, limit=1)

        if not instance:
            return request.make_response('{"status":"no_instance"}', headers=[("Content-Type", "application/json")])

        # Signature check (optional)
        if instance.webhook_secret and signature:
            computed = base64.b64encode(
                hmac.new(
                    instance.webhook_secret.encode("utf-8"),
                    raw,
                    hashlib.sha256,
                ).digest()
            ).decode("utf-8")
            if not hmac.compare_digest(computed, signature):
                _logger.warning("Woo webhook signature mismatch")
                return request.make_response('{"status":"invalid_signature"}', headers=[("Content-Type", "application/json")])

        Sync = request.env["woo.webhook.sync"].sudo()

        if topic in ("product.created", "product.updated"):
            if topic.endswith("created") and instance.webhook_product_create:
                Sync.sync_product(payload, instance, source_action="product_create")
            if topic.endswith("updated") and instance.webhook_product_update:
                Sync.sync_product(payload, instance, source_action="product_update")
        elif topic in ("customer.created", "customer.updated"):
            if topic.endswith("created") and instance.webhook_customer_create:
                Sync.sync_customer(payload, instance, source_action="customer_create")
            if topic.endswith("updated") and instance.webhook_customer_update:
                Sync.sync_customer(payload, instance, source_action="customer_update")
        elif topic in ("order.created", "order.updated"):
            if topic.endswith("created") and instance.webhook_order_create:
                Sync.sync_order(payload, instance, source_action="order_create")
            if topic.endswith("updated") and instance.webhook_order_update:
                Sync.sync_order(payload, instance, source_action="order_update")
        elif topic in ("product.category.created", "product.category.updated", "category.created", "category.updated"):
            if topic.endswith("created") and instance.webhook_category_create:
                Sync.sync_category(payload, instance, source_action="category_create")
            if topic.endswith("updated") and instance.webhook_category_update:
                Sync.sync_category(payload, instance, source_action="category_update")
        elif topic in ("coupon.created", "coupon.updated"):
            if topic.endswith("created") and instance.webhook_giftcard_create:
                Sync.sync_coupon(payload, instance, source_action="coupon_create")
            if topic.endswith("updated") and instance.webhook_giftcard_update:
                Sync.sync_coupon(payload, instance, source_action="coupon_update")
        else:
            _logger.info("Unhandled Woo webhook topic: %s", topic)

        return request.make_response('{"status":"ok"}', headers=[("Content-Type", "application/json")])

    @http.route(
        "/woo/webhook/order",
        type="json",
        auth="public",
        methods=["POST"],
        csrf=False,
    )
    def woo_order_webhook(self, **payload):
        """
        Dynamic Woo Order Status Webhook
        """
        _logger.info("Woo Order Webhook: %s", payload)

        woo_order_id = payload.get("id")
        woo_status = payload.get("status")

        if not woo_order_id:
            return {"status": "ignored"}

        order = request.env["woo.order.sync"].sudo().search(
            [("woo_order_id", "=", str(woo_order_id))],
            limit=1,
        )

        if not order:
            return {"status": "order_not_found"}

        order.write({
            "woo_status": woo_status,
            "synced_on": fields.Datetime.now(),
        })

        _logger.info(
            "Order %s updated dynamically to Woo status: %s",
            woo_order_id,
            woo_status,
        )

        return {"status": "success"}
