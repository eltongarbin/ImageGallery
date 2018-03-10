﻿using IdentityModel.Client;
using ImageGallery.Client.Services;
using ImageGallery.Client.ViewModels;
using ImageGallery.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace ImageGallery.Client.Controllers
{
    [Authorize]
    public class GalleryController : Controller
    {
        private readonly IImageGalleryHttpClient _imageGalleryHttpClient;

        public GalleryController(IImageGalleryHttpClient imageGalleryHttpClient)
        {
            _imageGalleryHttpClient = imageGalleryHttpClient;
        }

        public async Task<IActionResult> Index()
        {
            await WriteOutIdentityInformation();
            // call the API
            var httpClient = await _imageGalleryHttpClient.GetClient();

            var response = await httpClient.GetAsync("api/images").ConfigureAwait(false);
            return await HandleApiResponse(response, async () =>
            {
                var imagesAsString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var galleryIndexViewModel = new GalleryIndexViewModel(
                    JsonConvert.DeserializeObject<IList<Image>>(imagesAsString).ToList());

                return View(galleryIndexViewModel);
            });
        }

        public async Task<IActionResult> EditImage(Guid id)
        {
            // call the API
            var httpClient = await _imageGalleryHttpClient.GetClient();

            var response = await httpClient.GetAsync($"api/images/{id}").ConfigureAwait(false);
            return await HandleApiResponse(response, async () =>
            {
                var imageAsString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var deserializedImage = JsonConvert.DeserializeObject<Image>(imageAsString);

                var editImageViewModel = new EditImageViewModel()
                {
                    Id = deserializedImage.Id,
                    Title = deserializedImage.Title
                };

                return View(editImageViewModel);
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditImage(EditImageViewModel editImageViewModel)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // create an ImageForUpdate instance
            var imageForUpdate = new ImageForUpdate()
            { Title = editImageViewModel.Title };

            // serialize it
            var serializedImageForUpdate = JsonConvert.SerializeObject(imageForUpdate);

            // call the API
            var httpClient = await _imageGalleryHttpClient.GetClient();

            var response = await httpClient.PutAsync(
                $"api/images/{editImageViewModel.Id}",
                new StringContent(serializedImageForUpdate, System.Text.Encoding.Unicode, "application/json"))
                .ConfigureAwait(false);
            return HandleApiResponse(response, () => RedirectToAction("Index"));
        }

        public async Task<IActionResult> DeleteImage(Guid id)
        {
            // call the API
            var httpClient = await _imageGalleryHttpClient.GetClient();

            var response = await httpClient.DeleteAsync($"api/images/{id}").ConfigureAwait(false);
            return HandleApiResponse(response, () => RedirectToAction("Index"));
        }

        private async Task<IActionResult> HandleApiResponse(HttpResponseMessage response, Func<Task<IActionResult>> onSuccess)
        {
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    {
                        return await onSuccess();
                    }
                case HttpStatusCode.Unauthorized:
                case HttpStatusCode.Forbidden:
                    return RedirectToAction("AccessDenied", "Authorization");
                default:
                    throw new Exception($"A problem happened while calling the API: {response.ReasonPhrase}");
            }
        }

        private IActionResult HandleApiResponse(HttpResponseMessage response, Func<IActionResult> onSuccess)
        {
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                case HttpStatusCode.NoContent:
                case HttpStatusCode.Created:
                    {
                        return onSuccess();
                    }
                case HttpStatusCode.Unauthorized:
                case HttpStatusCode.Forbidden:
                    return RedirectToAction("AccessDenied", "Authorization");
                default:
                    throw new Exception($"A problem happened while calling the API: {response.ReasonPhrase}");
            }
        }

        [Authorize(Roles = "PayingUser")]
        public IActionResult AddImage()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "PayingUser")]
        public async Task<IActionResult> AddImage(AddImageViewModel addImageViewModel)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // create an ImageForCreation instance
            var imageForCreation = new ImageForCreation()
            { Title = addImageViewModel.Title };

            // take the first (only) file in the Files list
            var imageFile = addImageViewModel.Files.First();

            if (imageFile.Length > 0)
            {
                using (var fileStream = imageFile.OpenReadStream())
                using (var ms = new MemoryStream())
                {
                    fileStream.CopyTo(ms);
                    imageForCreation.Bytes = ms.ToArray();
                }
            }

            // serialize it
            var serializedImageForCreation = JsonConvert.SerializeObject(imageForCreation);

            // call the API
            var httpClient = await _imageGalleryHttpClient.GetClient();

            var response = await httpClient.PostAsync(
                $"api/images",
                new StringContent(serializedImageForCreation, System.Text.Encoding.Unicode, "application/json"))
                .ConfigureAwait(false);
            return HandleApiResponse(response, () => RedirectToAction("Index"));
        }

        public async Task Logout()
        {
            // get the metadata
            var discoveryClient = new DiscoveryClient("https://localhost:44373/");
            var metaDataResponse = await discoveryClient.GetAsync();

            // get revocation client
            var revocationClient = new TokenRevocationClient(metaDataResponse.RevocationEndpoint, "imagegalleryclient", "ItsMySecret");

            await RevokeAccessToken(revocationClient);
            await RevokeRefreshToken(revocationClient);

            // sign-out of authentication schemes
            await HttpContext.SignOutAsync("Cookies");
            await HttpContext.SignOutAsync("oidc");
        }

        private async Task RevokeAccessToken(TokenRevocationClient revocationClient)
        {
            // get access token
            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                // revoke access token
                var revokeAccessTokenResponse = await revocationClient.RevokeAccessTokenAsync(accessToken);
                if (revokeAccessTokenResponse.IsError)
                {
                    throw new Exception("Error occurred during revocation of access token", revokeAccessTokenResponse.Exception);
                }
            }
        }

        private async Task RevokeRefreshToken(TokenRevocationClient revocationClient)
        {
            // get refresh token
            var refreshToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);

            if (!string.IsNullOrWhiteSpace(refreshToken))
            {
                // revoke refresh token
                var revokeRefreshTokenResponse = await revocationClient.RevokeRefreshTokenAsync(refreshToken);
                if (revokeRefreshTokenResponse.IsError)
                {
                    throw new Exception("Error occurred during revocation of refresh token", revokeRefreshTokenResponse.Exception);
                }
            }
        }

        public async Task WriteOutIdentityInformation()
        {
            var identityToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
            Debug.WriteLine($"IdentityToken: {identityToken}");
            foreach (var claim in User.Claims)
            {
                Debug.WriteLine($"Claim type: {claim.Type}, claim value: {claim.Value}");
            }
        }

        [Authorize(Policy = "CanOrderFrame")]
        public async Task<ActionResult> OrderFrame()
        {
            var discoveryClient = new DiscoveryClient("https://localhost:44373/");
            var metaDataResponse = await discoveryClient.GetAsync();
            var userInfoClient = new UserInfoClient(metaDataResponse.UserInfoEndpoint);
            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            var response = await userInfoClient.GetAsync(accessToken);
            if (response.IsError)
                throw new Exception("Problem accessing UserInfo endpoint", response.Exception);

            var address = response.Claims.FirstOrDefault(c => c.Type == "address")?.Value;

            return View(new OrderFrameViewModel(address));
        }
    }
}
