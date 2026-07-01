#include "sign.hpp"
#include "log.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <Windows.h>
#include <wincrypt.h>

#include <memory>

namespace
{
    struct bio_deleter { void operator()(BIO* b) const { BIO_free(b); } };
    struct pkcs7_deleter { void operator()(PKCS7* p) const { PKCS7_free(p); } };
    struct x509_store_deleter { void operator()(X509_STORE* s) const { X509_STORE_free(s); } };
    struct x509_store_ctx_deleter { void operator()(X509_STORE_CTX* c) const { X509_STORE_CTX_free(c); } };

    using bio_ptr = std::unique_ptr<BIO, bio_deleter>;
    using pkcs7_ptr = std::unique_ptr<PKCS7, pkcs7_deleter>;
    using x509_store_ptr = std::unique_ptr<X509_STORE, x509_store_deleter>;
    using x509_store_ctx_ptr = std::unique_ptr<X509_STORE_CTX, x509_store_ctx_deleter>;

    x509_store_ptr create_trust_store()
    {
        auto store = x509_store_ptr(X509_STORE_new());
        if (!store)
        {
            return nullptr;
        }

        auto* sys_store = CertOpenSystemStoreW(0, L"Root");
        if (!sys_store)
        {
            LOG_WARN("failed to open system root certificate store");
            return store;
        }

        int count = 0;
        const CERT_CONTEXT* ctx = nullptr;

        while ((ctx = CertEnumCertificatesInStore(sys_store, ctx)) != nullptr)
        {
            const auto* der = ctx->pbCertEncoded;
            auto* cert = d2i_X509(nullptr, &der, static_cast<long>(ctx->cbCertEncoded));

            if (cert)
            {
                X509_STORE_add_cert(store.get(), cert);
                X509_free(cert);
                ++count;
            }
        }

        CertCloseStore(sys_store, 0);
        LOG_INFO("loaded {} trusted root certificates from system store", count);
        return store;
    }

    bool verify_chain(STACK_OF(X509)* signers, STACK_OF(X509)* all_certs, X509_STORE* store)
    {
        if (!signers || sk_X509_num(signers) == 0)
        {
            return false;
        }

        for (int i = 0; i < sk_X509_num(signers); ++i)
        {
            auto ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
            if (!ctx)
            {
                return false;
            }

            if (X509_STORE_CTX_init(ctx.get(), store, sk_X509_value(signers, i), all_certs) != 1)
            {
                return false;
            }

            X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(ctx.get()), X509_V_FLAG_NO_CHECK_TIME);

            if (X509_verify_cert(ctx.get()) != 1)
            {
                LOG_WARN("chain verification failed: {} ({})",
                    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get())),
                    X509_STORE_CTX_get_error(ctx.get()));
                return false;
            }
        }

        return true;
    }

    pkcs7_ptr parse_pkcs7(std::span<const std::uint8_t> der)
    {
        auto bio = bio_ptr(BIO_new_mem_buf(der.data(), static_cast<int>(der.size())));
        if (!bio)
        {
            return nullptr;
        }

        return pkcs7_ptr(d2i_PKCS7_bio(bio.get(), nullptr));
    }

    bool verify_pkcs7_chain(PKCS7* p7)
    {
        auto* signers = PKCS7_get0_signers(p7, nullptr, PKCS7_NOVERIFY);
        if (!signers)
        {
            return false;
        }

        auto store = create_trust_store();
        if (!store)
        {
            sk_X509_free(signers);
            return false;
        }

        auto* all_certs = p7->d.sign ? p7->d.sign->cert : nullptr;
        const bool valid = verify_chain(signers, all_certs, store.get());
        sk_X509_free(signers);
        return valid;
    }
}

namespace sign
{
    bool verify_embedded(std::span<const std::uint8_t> pkcs7_der)
    {
        auto p7 = parse_pkcs7(pkcs7_der);
        if (!p7)
        {
            return false;
        }

        return verify_pkcs7_chain(p7.get());
    }

    bool verify_catalog(std::span<const std::uint8_t> catalog_pkcs7,
                        std::span<const std::uint8_t> authenticode_hash)
    {
        auto p7 = parse_pkcs7(catalog_pkcs7);
        if (!p7)
        {
            return false;
        }

        if (!verify_pkcs7_chain(p7.get()))
        {
            return false;
        }

        const auto* signed_data = p7->d.sign;
        if (!signed_data || !signed_data->contents || !signed_data->contents->d.other)
        {
            return false;
        }

        const auto* content = signed_data->contents->d.other->value.octet_string;
        if (!content || !content->data || content->length <= 0 || authenticode_hash.empty())
        {
            return false;
        }

        const auto* haystack = content->data;
        const auto haystack_len = static_cast<std::size_t>(content->length);
        const auto needle_len = authenticode_hash.size();

        for (std::size_t i = 0; i + needle_len <= haystack_len; ++i)
        {
            if (std::memcmp(haystack + i, authenticode_hash.data(), needle_len) == 0)
            {
                return true;
            }
        }

        return false;
    }
}
